# Руководство по устранению CSRF-уязвимостей

## Обнаруженные уязвимости

Ваш веб-сканер обнаружил следующие CSRF-уязвимости:

1. **`/personal/index.php?login=yes`** (метод: POST)
2. **`/dpo/kursy/`** (метод: POST)
3. **`/about_the_college/virtualnaya-priemnaya/`** (метод: POST)
4. **`/applicants/admission_request/`** (метод: POST)
5. **`./Login.aspx?ReturnUrl=%2fpersonal`** (метод: POST)
6. **`/uk/`** (метод: POST)

## Что такое CSRF-атака?

**Cross-Site Request Forgery (CSRF)** - это атака, при которой злоумышленник заставляет аутентифицированного пользователя выполнить нежелательные действия на веб-сайте, на котором пользователь в данный момент аутентифицирован.

## Рекомендации по устранению

### 1. Внедрение CSRF-токенов

#### Для PHP-приложений (`.php` файлы):

```php
<?php
session_start();

// Генерация CSRF-токена
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// В HTML-форме
?>
<form method="POST" action="/personal/index.php?login=yes">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <!-- остальные поля формы -->
    <input type="text" name="username" required>
    <input type="password" name="password" required>
    <button type="submit">Войти</button>
</form>

<?php
// Проверка токена при обработке формы
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    // Обработка формы
}
?>
```

#### Для ASP.NET приложений (`.aspx` файлы):

```aspx
<%@ Page Language="C#" %>
<form method="POST" action="./Login.aspx?ReturnUrl=%2fpersonal">
    <%: Html.AntiForgeryToken() %>
    <!-- остальные поля формы -->
    <input type="text" name="username" required />
    <input type="password" name="password" required />
    <button type="submit">Войти</button>
</form>
```

```csharp
// В code-behind
[ValidateAntiForgeryToken]
public ActionResult Login(LoginModel model)
{
    // Обработка входа
}
```

### 2. Использование SameSite cookies

```php
// Установка SameSite атрибута для cookies
session_set_cookie_params([
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);
session_start();
```

### 3. Проверка Referer заголовка

```php
function validateReferer() {
    $allowedDomains = ['yourdomain.com', 'www.yourdomain.com'];
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    
    if (empty($referer)) {
        return false;
    }
    
    $refererHost = parse_url($referer, PHP_URL_HOST);
    return in_array($refererHost, $allowedDomains);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateReferer()) {
        http_response_code(403);
        die('Invalid referer');
    }
    // Обработка формы
}
```

### 4. Использование двойной отправки cookies

```javascript
// JavaScript для двойной отправки cookies
function submitFormWithDoubleCookie(form) {
    // Получаем CSRF-токен из cookie
    const token = getCookie('csrf_token');
    
    // Добавляем токен в форму
    const tokenInput = document.createElement('input');
    tokenInput.type = 'hidden';
    tokenInput.name = 'csrf_token';
    tokenInput.value = token;
    form.appendChild(tokenInput);
    
    return true;
}
```

### 5. Временные ограничения для токенов

```php
// Генерация токена с временной меткой
$_SESSION['csrf_token'] = [
    'token' => bin2hex(random_bytes(32)),
    'expires' => time() + 3600 // Токен действителен 1 час
];

// Проверка токена
if (isset($_POST['csrf_token'])) {
    $tokenData = $_SESSION['csrf_token'];
    if (time() > $tokenData['expires']) {
        // Токен истек
        unset($_SESSION['csrf_token']);
        http_response_code(403);
        die('CSRF token expired');
    }
    
    if ($_POST['csrf_token'] !== $tokenData['token']) {
        http_response_code(403);
        die('Invalid CSRF token');
    }
}
```

## Специфические рекомендации по файлам

### 1. `/personal/index.php?login=yes`

```php
<?php
// login.php
session_start();

// Генерация токена при загрузке страницы входа
if (!isset($_SESSION['login_csrf_token'])) {
    $_SESSION['login_csrf_token'] = bin2hex(random_bytes(32));
}

// В форме входа
?>
<form method="POST" action="/personal/index.php?login=yes">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['login_csrf_token']; ?>">
    <input type="text" name="username" placeholder="Имя пользователя" required>
    <input type="password" name="password" placeholder="Пароль" required>
    <button type="submit">Войти</button>
</form>

<?php
// Обработка входа
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['login_csrf_token']) {
        http_response_code(403);
        die('Ошибка безопасности: недействительный токен');
    }
    
    // Удаляем использованный токен
    unset($_SESSION['login_csrf_token']);
    
    // Обработка входа
    $username = $_POST['username'];
    $password = $_POST['password'];
    // ... логика аутентификации
}
?>
```

### 2. `/dpo/kursy/` и `/about_the_college/virtualnaya-priemnaya/`

```php
<?php
// Для форм обратной связи и заявок
session_start();

if (!isset($_SESSION['form_csrf_token'])) {
    $_SESSION['form_csrf_token'] = bin2hex(random_bytes(32));
}
?>

<form method="POST" action="/dpo/kursy/">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['form_csrf_token']; ?>">
    <input type="text" name="name" placeholder="Ваше имя" required>
    <input type="email" name="email" placeholder="Email" required>
    <textarea name="message" placeholder="Сообщение" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

### 3. `/applicants/admission_request/`

```php
<?php
// Для формы подачи заявления
session_start();

if (!isset($_SESSION['admission_csrf_token'])) {
    $_SESSION['admission_csrf_token'] = bin2hex(random_bytes(32));
}
?>

<form method="POST" action="/applicants/admission_request/">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admission_csrf_token']; ?>">
    <!-- Поля формы заявления -->
    <input type="text" name="full_name" placeholder="ФИО" required>
    <input type="email" name="email" placeholder="Email" required>
    <input type="tel" name="phone" placeholder="Телефон" required>
    <button type="submit">Подать заявление</button>
</form>
```

### 4. `./Login.aspx?ReturnUrl=%2fpersonal`

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Mvc" %>

<form method="POST" action="./Login.aspx?ReturnUrl=%2fpersonal">
    <%: Html.AntiForgeryToken() %>
    <input type="text" name="username" placeholder="Имя пользователя" required />
    <input type="password" name="password" placeholder="Пароль" required />
    <button type="submit">Войти</button>
</form>
```

```csharp
// В контроллере
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult Login(LoginModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        // Логика аутентификации
        if (AuthenticateUser(model))
        {
            return Redirect(returnUrl ?? "/personal");
        }
    }
    return View(model);
}
```

## Дополнительные меры безопасности

### 1. HTTP-заголовки безопасности

```php
// Установка заголовков безопасности
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
```

### 2. Валидация Content-Type

```php
// Проверка Content-Type для AJAX-запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (strpos($contentType, 'application/x-www-form-urlencoded') === false &&
        strpos($contentType, 'multipart/form-data') === false) {
        http_response_code(400);
        die('Invalid Content-Type');
    }
}
```

### 3. Логирование попыток CSRF-атак

```php
function logCsrfAttempt($ip, $userAgent, $url) {
    $logEntry = date('Y-m-d H:i:s') . " - CSRF attempt from IP: $ip, User-Agent: $userAgent, URL: $url\n";
    file_put_contents('/var/log/csrf_attempts.log', $logEntry, FILE_APPEND | LOCK_EX);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        logCsrfAttempt($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], $_SERVER['REQUEST_URI']);
        http_response_code(403);
        die('CSRF token validation failed');
    }
}
```

## Проверка реализации

После внедрения CSRF-защиты используйте ваш веб-сканер для повторного тестирования:

1. Запустите сканирование на тех же URL
2. Убедитесь, что CSRF-уязвимости больше не обнаруживаются
3. Проверьте функциональность форм вручную

## Мониторинг и поддержка

1. **Регулярное обновление токенов**: Обновляйте CSRF-токены при каждой сессии
2. **Мониторинг логов**: Отслеживайте попытки CSRF-атак
3. **Тестирование**: Регулярно проводите тестирование безопасности
4. **Обновления**: Следите за обновлениями фреймворков и библиотек

## Заключение

Внедрение CSRF-токенов является критически важной мерой безопасности для всех форм, которые обрабатывают данные пользователей. Реализуйте предложенные меры поэтапно, начиная с наиболее критичных форм (вход в систему, подача заявлений), и регулярно тестируйте их эффективность. 