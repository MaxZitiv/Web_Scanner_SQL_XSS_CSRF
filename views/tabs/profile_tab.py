from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QFormLayout, QLabel, 
    QPushButton, QFileDialog, QHBoxLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from utils.logger import logger, log_and_notify
from utils.error_handler import error_handler
from utils.performance import get_local_timestamp
from utils.database import db
import json
import os
from datetime import datetime

class ProfileTabWidget(QWidget):
    def __init__(self, user_id, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # User information group
        user_info_group = QGroupBox("Информация о пользователе")
        user_info_layout = QFormLayout()
        
        # Username
        self.username_label = QLabel()
        user_info_layout.addRow("Имя пользователя:", self.username_label)
        
        # Email
        self.email_label = QLabel()
        user_info_layout.addRow("Email:", self.email_label)
        
        # Registration date
        self.reg_date_label = QLabel()
        user_info_layout.addRow("Дата регистрации:", self.reg_date_label)
        
        # Last login
        self.last_login_label = QLabel()
        user_info_layout.addRow("Последний вход:", self.last_login_label)
        
        user_info_group.setLayout(user_info_layout)
        layout.addWidget(user_info_group)
        
        # Statistics group
        stats_group = QGroupBox("Статистика сканирования")
        stats_layout = QFormLayout()
        
        # Total scans
        self.total_scans_label = QLabel("0")
        stats_layout.addRow("Всего сканирований:", self.total_scans_label)
        
        # Successful scans
        self.successful_scans_label = QLabel("0")
        stats_layout.addRow("Успешных сканирований:", self.successful_scans_label)
        
        # Failed scans
        self.failed_scans_label = QLabel("0")
        stats_layout.addRow("Неудачных сканирований:", self.failed_scans_label)
        
        # Vulnerabilities found
        self.vulns_found_label = QLabel("0")
        stats_layout.addRow("Найдено уязвимостей:", self.vulns_found_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Avatar group
        avatar_group = QGroupBox("Аватар")
        avatar_layout = QVBoxLayout()
        
        self.avatar_label = QLabel()
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setMinimumSize(200, 200)
        self.avatar_label.setStyleSheet("border: 1px solid gray")
        avatar_layout.addWidget(self.avatar_label)
        
        avatar_buttons_layout = QHBoxLayout()
        
        self.change_avatar_button = QPushButton("Изменить аватар")
        self.change_avatar_button.clicked.connect(self.change_avatar)
        avatar_buttons_layout.addWidget(self.change_avatar_button)
        
        self.remove_avatar_button = QPushButton("Удалить аватар")
        self.remove_avatar_button.clicked.connect(self.remove_avatar)
        avatar_buttons_layout.addWidget(self.remove_avatar_button)
        
        avatar_layout.addLayout(avatar_buttons_layout)
        avatar_group.setLayout(avatar_layout)
        layout.addWidget(avatar_group)
        
        # Update profile button
        self.update_profile_button = QPushButton("Обновить профиль")
        self.update_profile_button.clicked.connect(self.update_profile)
        layout.addWidget(self.update_profile_button)
        
        # Load user data
        self.load_user_data()
        
    def load_user_data(self):
        try:
            user_data = db.get_user_by_id(self.user_id)
            if user_data:
                self.username_label.setText(user_data.get('username', ''))
                self.email_label.setText(user_data.get('email', ''))
                self.reg_date_label.setText(user_data.get('registration_date', ''))
                self.last_login_label.setText(user_data.get('last_login', ''))
                
                # Load avatar if exists
                avatar_path = user_data.get('avatar_path', '')
                if avatar_path and os.path.exists(avatar_path):
                    pixmap = QPixmap(avatar_path)
                    self.avatar_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                
                # Load scan statistics
                self.load_scan_statistics()
        except Exception as e:
            error_handler.handle_database_error(e, "load_user_data")
            log_and_notify('error', f"Error loading user data: {e}")
    
    def load_scan_statistics(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if scans:
                total_scans = len(scans)
                successful_scans = sum(1 for scan in scans if scan.get('status') == 'completed')
                failed_scans = total_scans - successful_scans
                
                total_vulns = 0
                for scan in scans:
                    results = scan.get('result', scan.get('results', []))
                    if isinstance(results, str):
                        try:
                            results = json.loads(results)
                        except (json.JSONDecodeError, TypeError):
                            results = []
                    total_vulns += len(results)
                
                self.total_scans_label.setText(str(total_scans))
                self.successful_scans_label.setText(str(successful_scans))
                self.failed_scans_label.setText(str(failed_scans))
                self.vulns_found_label.setText(str(total_vulns))
        except Exception as e:
            error_handler.handle_database_error(e, "load_scan_statistics")
            log_and_notify('error', f"Error loading scan statistics: {e}")
    
    def change_avatar(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Выберите аватар", "", "Images (*.png *.jpg *.jpeg *.bmp)"
            )
            if file_path:
                # Save avatar to user's data directory
                user_dir = os.path.join("data", "avatars", str(self.user_id))
                os.makedirs(user_dir, exist_ok=True)
                
                avatar_name = f"avatar_{get_local_timestamp().replace(':', '').replace(' ', '_')}{os.path.splitext(file_path)[1]}"
                avatar_path = os.path.join(user_dir, avatar_name)
                
                # Copy image to user's directory
                import shutil
                shutil.copy2(file_path, avatar_path)
                
                # Update database using get_db_connection_cm
                with db.get_db_connection_cm() as conn:
                    conn.execute(
                        "UPDATE users SET avatar_path = ? WHERE id = ?",
                        (avatar_path, self.user_id)
                    )
                    
                # Update UI
                pixmap = QPixmap(avatar_path)
                self.avatar_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                
                log_and_notify('info', "Avatar updated successfully")
        except Exception as e:
            error_handler.handle_file_error(e, "change_avatar")
            log_and_notify('error', f"Error changing avatar: {e}")
    
    def remove_avatar(self):
        try:
            # Get current avatar path
            user_data = db.get_user_by_id(self.user_id)
            if user_data:
                avatar_path = user_data.get('avatar_path', '')
                if avatar_path and os.path.exists(avatar_path):
                    os.remove(avatar_path)
                
                # Update database using get_db_connection_cm
                with db.get_db_connection_cm() as conn:
                    conn.execute(
                        "UPDATE users SET avatar_path = NULL WHERE id = ?",
                        (self.user_id,)
                    )
            
                
                # Update UI
                self.avatar_label.clear()
                
                log_and_notify('info', "Avatar removed successfully")
        except Exception as e:
            error_handler.handle_file_error(e, "remove_avatar")
            log_and_notify('error', f"Error removing avatar: {e}")
    
    def update_profile(self):
        try:
            from views.edit_profile_window import EditProfileWindow
            user_data = db.get_user_by_id(self.user_id)
            username = user_data.get('username', '') if user_data else ''
            edit_window = EditProfileWindow(self.user_id, username, self)
            if edit_window.exec_():
                # Refresh data after profile update
                self.load_user_data()
        except Exception as e:
            error_handler.handle_validation_error(e, "update_profile")
            log_and_notify('error', f"Error updating profile: {e}")

    def set_avatar(self, pixmap):
        """Установка аватара пользователя"""
        try:
            if hasattr(self, 'avatar_label'):
                self.avatar_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
        except Exception as e:
            logger.exception(f"Error setting avatar: {str(e)}")
            log_and_notify('error', f"Error setting avatar: {e}")

    def set_default_avatar(self):
        """Установка аватара по умолчанию"""
        try:
            if hasattr(self, 'avatar_label'):
                self.avatar_label.clear()
                self.avatar_label.setText("Аватар по умолчанию")
        except Exception as e:
            logger.exception(f"Error setting default avatar: {str(e)}")