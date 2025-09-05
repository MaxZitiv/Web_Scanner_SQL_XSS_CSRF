from typing import Optional
from PyQt5.QtWidgets import QMainWindow, QStackedWidget, QGraphicsOpacityEffect, QWidget, QMessageBox
from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QIcon, QCloseEvent

from utils import error_handler, performance
from utils.performance import measure_time
from views.login_window import LoginWindow
from ui.registration_window import RegistrationWindow
from views.dashboard_window import DashboardWindow
from utils.cache_cleanup import cleanup_on_exit
from utils.logger import logger, log_and_notify
from utils.database import db

class MainWindow(QMainWindow):
    def __init__(self, user_model, parent: Optional[QMainWindow] = None) -> None:
        super().__init__(parent)
        self.user_model = user_model
        self.setWindowTitle("Web Scanner")
        self.setWindowIcon(QIcon(db.get_resource_path("default_avatar.ico")))
        self.setGeometry(100, 100, 1200, 800)
        self.stack: QStackedWidget = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Создаем объекты окон
        self.login_window = LoginWindow(self.user_model, self)
        self.registration_window = RegistrationWindow(self.login_window)
        self.dashboard_window: Optional[DashboardWindow] = None

        # Подключаем сигналы
        self.login_window.login_successful.connect(self.show_dashboard)

        self._current_animation: Optional[QPropertyAnimation] = None
        self.stack.addWidget(self.login_window)
        self.stack.addWidget(self.registration_window)
        self.stack.setCurrentWidget(self.login_window)

        # Безопасно подстраиваем размер окна под текущее состояние
        self.safe_resize_window(self.login_window)

        # Центрируем окно на экране
        self.center_window()

        # Инициализируем компоненты
        self.init_ui_components()

    def init_ui_components(self):
        """Инициализация всех необходимых UI компонентов"""
        try:
            # Проверяем stack
            if not hasattr(self, 'stack') or not isinstance(self.stack, QStackedWidget):
                raise ValueError("Stack widget not properly initialized")

            # Проверяем login_window
            if not hasattr(self, 'login_window') or not isinstance(self.login_window, LoginWindow):
                raise ValueError("Login window not properly initialized")

            # Проверяем registration_window
            if not hasattr(self, 'registration_window') or not isinstance(self.registration_window, RegistrationWindow):
                raise ValueError("Registration window not properly initialized")

            # Проверяем dashboard_window (может быть None, это нормально)
            if hasattr(self, 'dashboard_window') and self.dashboard_window is not None and not isinstance(self.dashboard_window, DashboardWindow):
                raise ValueError("Dashboard window not properly initialized")

            # Проверяем подключение сигналов
            if not hasattr(self, 'login_window') or not self.login_window.receivers(self.login_window.login_successful):
                raise ValueError("Login signal not properly connected")

            logger.info("All UI components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize UI components: {e}")
            raise

    def safe_resize_window(self, widget: QWidget):
        """Безопасно изменяет размер окна с учетом ограничений экрана"""
        try:
            widget_size = widget.sizeHint()
            if not widget_size.isValid():
                return

            # Получаем доступную геометрию экрана
            screen = self.screen()
            if screen is None:
                logger.warning("Screen is None, cannot resize window")
                return

            screen_geometry = screen.availableGeometry()

            # Вычисляем желаемый размер окна (с запасом для рамки)
            desired_width = widget_size.width() + 40
            desired_height = widget_size.height() + 40

            # Ограничиваем размер доступной областью экрана
            max_width = min(desired_width, screen_geometry.width() - 50)
            max_height = min(desired_height, screen_geometry.height() - 50)

            # Устанавливаем размер с учетом минимальных ограничений
            new_width = max(max_width, self.minimumWidth())
            new_height = max(max_height, self.minimumHeight())

            # Изменяем размер окна
            self.resize(new_width, new_height)

            logger.debug(f"Window resized to {new_width}x{new_height} (desired: {desired_width}x{desired_height})")

        except (ValueError, TypeError, AttributeError, OSError) as e:
            logger.warning(f"Error resizing window: {e}")
        except Exception as e:
            log_and_notify('error', f"Unexpected error resizing window: {e}")

    def center_window(self):
        """Центрирует окно на экране"""
        try:
            frame_geometry = self.frameGeometry()
            screen = self.screen()
            if screen is None:
                logger.warning("Screen is None, cannot center window")
                return

            screen_center = screen.availableGeometry().center()
            frame_geometry.moveCenter(screen_center)
            self.move(frame_geometry.topLeft())
        except (ValueError, TypeError, AttributeError, OSError) as e:
            logger.warning(f"Error centering window: {e}")
        except Exception as e:
            log_and_notify('error', f"Unexpected error centering window: {e}")

    def fade_to_widget(self, widget):
        opacity_effect = QGraphicsOpacityEffect()
        widget.setGraphicsEffect(opacity_effect)

        self.stack.setCurrentWidget(widget)

        # Безопасно подстраиваем размер окна под текущее содержимое
        self.safe_resize_window(widget)

        # Если переключаемся на окно авторизации, убираем максимизацию
        if widget == self.login_window:
            self.showNormal()

        # Центрируем окно
        self.center_window()

        animation = QPropertyAnimation(opacity_effect, b"opacity", self)
        animation.setDuration(500)
        animation.setStartValue(0)
        animation.setEndValue(1)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.start()

        # Не даём GC уничтожить анимацию сразу
        self._current_animation = animation

    def go_to_registration(self):
        try:
            # Проверка инициализации компонентов
            if not hasattr(self, 'stack') or not hasattr(self, 'registration_window'):
                logger.error("Stack or registration window not initialized")
                return

            self.stack.setCurrentWidget(self.registration_window)
            self.safe_resize_window(self.registration_window)

        except Exception as e:
            logger.error(f"Error navigating to registration: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось перейти к регистрации: {e}")

    def go_to_login(self):
        # Сначала скрываем dashboard_window если он существует
        if self.dashboard_window is not None:
            self.dashboard_window.hide()
            self.stack.removeWidget(self.dashboard_window)
            self.dashboard_window.deleteLater()
            self.dashboard_window = None

        # Затем переключаемся на окно авторизации
        self.fade_to_widget(self.login_window)


    @measure_time
    def go_to_dashboard(self, user_id, username):
        try:
            # Проверка инициализации компонентов
            if not hasattr(self, 'stack'):
                logger.error("Stack not initialized")
                return

            # Создаем dashboard_window при первом обращении
            if not hasattr(self, 'dashboard_window') or self.dashboard_window is None:
                self.dashboard_window = DashboardWindow(user_id, username, self)
                self.stack.addWidget(self.dashboard_window)

            self.stack.setCurrentWidget(self.dashboard_window)
            self.safe_resize_window(self.dashboard_window)

            # Максимизируем окно после перехода к дашборду
            self.showMaximized()

        except Exception as e:
            logger.error(f"Error navigating to dashboard: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось перейти к панели управления: {e}")


    def safe_maximize_window(self):
        """Безопасно максимизирует окно с учетом ограничений экрана"""
        try:
            # Проверяем, что окно не уже максимизировано
            if not self.isMaximized():
                # Получаем доступную геометрию экрана
                screen = self.screen()
                if screen is None:
                    logger.warning("Screen is None, cannot maximize window")
                    return

                screen_geometry = screen.availableGeometry()

                # Проверяем, что окно помещается на экране
                current_geometry = self.geometry()
                if (current_geometry.width() <= screen_geometry.width() and
                    current_geometry.height() <= screen_geometry.height()):
                    self.showMaximized()
                    logger.debug("Window maximized successfully")
                else:
                    logger.warning("Window too large for screen, keeping normal size")
            else:
                logger.debug("Window already maximized")

        except (ValueError, TypeError, AttributeError, OSError) as e:
            logger.warning(f"Error maximizing window: {e}")
            # В случае ошибки просто показываем окно в нормальном размере
            self.showNormal()
        except Exception as e:
            log_and_notify('error', f"Unexpected error maximizing window: {e}")
            # В случае ошибки просто показываем окно в нормальном размере
            self.showNormal()

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        """Обработчик закрытия главного окна: очищает кэши перед выходом"""
        try:
            # Проверяем настройку пользователя для очистки кэшей
            should_clear_cache = True

            # Если есть dashboard_window, проверяем настройку
            if hasattr(self, 'dashboard_window') and self.dashboard_window:
                if hasattr(self.dashboard_window, 'clear_cache_checkbox'):
                    should_clear_cache = self.dashboard_window.clear_cache_checkbox.isChecked()

            if should_clear_cache:
                logger.info("Main window closing, performing cache cleanup...")

                # Очищаем кэши перед закрытием
                cleanup_result = cleanup_on_exit(safe_mode=True)

                if cleanup_result.get('all_successful', False):
                    logger.info("Cache cleanup completed successfully before window close")
                else:
                    logger.warning("Cache cleanup completed with some errors before window close")

                # Логируем статистику очистки
                duration = cleanup_result.get('duration_seconds', 0)
                entries_freed = cleanup_result.get('entries_freed', 0)
                memory_freed = cleanup_result.get('memory_freed_mb', 0)

                logger.info(f"Pre-close cleanup stats: {duration:.3f}s, {entries_freed} entries, {memory_freed:.2f}MB memory")
            else:
                logger.info("Cache cleanup skipped due to user settings")

        except (ValueError, TypeError, AttributeError, OSError) as e:
            log_and_notify('error', f"Error during cache cleanup on window close: {e}")
        except Exception as e:
            log_and_notify('error', f"Unexpected error during cache cleanup on window close: {e}")

        # Принимаем событие закрытия
        if a0:
            a0.accept()
        else:
            super().closeEvent(a0)

    def show_dashboard(self, user_id, username):
        """Показывает главное окно приложения после успешной аутентификации"""
        try:
            # Создаем экземпляр UserModel, если его нет
            if not hasattr(self, 'user_model') or self.user_model is None:
                from models.user_model import UserModel
                self.user_model = UserModel()

            # Проверка инициализации компонентов
            if not hasattr(self, 'stack'):
                logger.error("Stack not initialized")
                return

            # Создаем dashboard_window при первом обращении
            if not hasattr(self, 'dashboard_window') or self.dashboard_window is None:
                self.dashboard_window = DashboardWindow(user_id, username, self.user_model, self)
                self.stack.addWidget(self.dashboard_window)

            self.stack.setCurrentWidget(self.dashboard_window)
            self.safe_resize_window(self.dashboard_window)

            # Максимизируем окно после перехода к дашборду
            self.showMaximized()

        except Exception as e:
            logger.error(f"Error showing dashboard: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось показать панель управления: {e}")