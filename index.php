<?php
session_start();

// --- CONFIGURATION ---
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');     // Your DB Username
define('DB_PASSWORD', ''); // Your DB Password
define('DB_NAME', 'pdf_store_v2'); // Your DB Name

// --- HELPER FUNCTIONS ---
function connectDB() {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error . ". Please check DB credentials in index.php.");
    }
    return $conn;
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isLoggedIn() && isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin';
}

function sanitize($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// --- COURSE DATA (Updated Prices in Rupees, and new Cloud Computing images) ---
$courses = [
    1 => ['id' => 1, 'name' => 'Web Development Fundamentals', 'price' => 49, 'pdf_file' => 'web_dev.pdf', 'description' => 'Master HTML, CSS, and JavaScript.', 'image_url' => 'https://images.unsplash.com/photo-1542831371-29b0f74f9713?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1461749280684-dccba630e2f6?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    2 => ['id' => 2, 'name' => 'Graphic Design Principles', 'price' => 39, 'pdf_file' => 'graphic_design.pdf', 'description' => 'Core concepts of visual communication.', 'image_url' => 'https://images.unsplash.com/photo-1626785774573-4b799315345d?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1522120691812-284505691399?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    3 => ['id' => 3, 'name' => 'Python for Data Science', 'price' => 59, 'pdf_file' => 'python_data.pdf', 'description' => 'Python for data analysis & ML.', 'image_url' => 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1504639725590-34d0984388bd?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    4 => ['id' => 4, 'name' => 'Digital Marketing Mastery', 'price' => 45, 'pdf_file' => 'digital_marketing.pdf', 'description' => 'SEO, SEM, social media strategies.', 'image_url' => 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1557804506-669a67965ba0?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    5 => ['id' => 5, 'name' => 'Mobile App Development (React Native)', 'price' => 69, 'pdf_file' => 'mobile_app_react.pdf', 'description' => 'Cross-platform mobile apps.', 'image_url' => 'https://images.unsplash.com/photo-1607706189992-eae578626c86?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1551650975-87deedd944c3?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    6 => ['id' => 6, 'name' => 'Cybersecurity Essentials', 'price' => 55, 'pdf_file' => 'cybersecurity.pdf', 'description' => 'Understand digital threats & defenses.', 'image_url' => 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1618060932014-4deda4932554?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
    7 => ['id' => 7, 'name' => 'Cloud Computing with AWS', 'price' => 79, 'pdf_file' => 'aws_cloud.pdf', 'description' => 'Deploy and manage on AWS.', 'image_url' => 'https://images.unsplash.com/photo-1580894906475-403276d3942d?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1611002211480-555917a1a49d?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'], // New AWS Images
    8 => ['id' => 8, 'name' => 'Project Management (PMP Prep)', 'price' => 89, 'pdf_file' => 'pmp_prep.pdf', 'description' => 'Prepare for PMP certification.', 'image_url' => 'https://images.unsplash.com/photo-1517048676732-d65bc937f952?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80', 'hero_image' => 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80'],
];
$slider_courses_ids = [1, 7, 3, 5]; // Included AWS in slider

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

$status_message = ''; $status_type = '';
function set_status_message($message, $type) {
    $_SESSION['flash_message'] = ['message' => $message, 'type' => $type];
}
if(isset($_SESSION['flash_message'])){
    $status_message = $_SESSION['flash_message']['message'];
    $status_type = $_SESSION['flash_message']['type'];
    unset($_SESSION['flash_message']);
}

function getCartItemCount() {
    return count($_SESSION['cart']);
}
function getCartTotal() {
    $total = 0;
    global $courses; 
    foreach ($_SESSION['cart'] as $course_id => $item) {
        if(isset($courses[$course_id])) {
             $total += $courses[$course_id]['price'];
        } else { 
            unset($_SESSION['cart'][$course_id]);
        }
    }
    return $total;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['action'])) {
    $action = $_POST['action'] ?? $_GET['action'] ?? '';
    $conn = null;
    $db_actions = ['register', 'login', 'process_payment', 'confirm_order'];
    if (in_array($action, $db_actions)) {
        $conn = connectDB();
    }

    if ($action === 'add_to_cart') {
        header('Content-Type: application/json');
        $response = ['success' => false, 'message' => 'Failed to add to cart.', 'cart_count' => getCartItemCount()];
        $course_id = isset($_POST['course_id']) ? intval($_POST['course_id']) : 0;
        if ($course_id > 0 && isset($courses[$course_id])) {
            if (!isset($_SESSION['cart'][$course_id])) {
                $_SESSION['cart'][$course_id] = $courses[$course_id];
                $response['success'] = true;
                $response['message'] = htmlspecialchars($courses[$course_id]['name']) . ' added to cart!';
            } else {
                $response['message'] = htmlspecialchars($courses[$course_id]['name']) . ' is already in cart.';
            }
        } else { $response['message'] = 'Invalid course.'; }
        $response['cart_count'] = getCartItemCount();
        echo json_encode($response);
        exit;
    } elseif ($action === 'remove_from_cart') {
        $course_id_to_remove = isset($_GET['course_id']) ? intval($_GET['course_id']) : 0;
        if ($course_id_to_remove > 0 && isset($_SESSION['cart'][$course_id_to_remove])) {
            $removed_item_name = $_SESSION['cart'][$course_id_to_remove]['name'];
            unset($_SESSION['cart'][$course_id_to_remove]);
            set_status_message(htmlspecialchars($removed_item_name) . ' removed from cart.', 'success');
        }
        header("Location: index.php?view=cart");
        exit;
    }
    elseif ($action === 'register') {
        $username = sanitize($_POST['username']); $email = filter_var(sanitize($_POST['email']), FILTER_SANITIZE_EMAIL); $password = $_POST['password']; $confirm_password = $_POST['confirm_password'];
        if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) { set_status_message('All fields are required.', 'error');
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { set_status_message('Invalid email format.', 'error');
        } elseif (strlen($password) < 6) { set_status_message('Password must be at least 6 characters.', 'error');
        } elseif ($password !== $confirm_password) { set_status_message('Passwords do not match.', 'error');
        } else {
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?"); $stmt->bind_param("ss", $username, $email); $stmt->execute(); $stmt->store_result();
            if ($stmt->num_rows > 0) { set_status_message('Username or email already taken.', 'error');
            } else {
                $password_hash = hashPassword($password); $stmt_insert = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"); $stmt_insert->bind_param("sss", $username, $email, $password_hash);
                if ($stmt_insert->execute()) { set_status_message('Registration successful! You can now login.', 'success'); $_GET['view'] = 'login';
                } else { set_status_message('Registration failed. Please try again.', 'error'); }
                $stmt_insert->close();
            } $stmt->close();
        }
    } elseif ($action === 'login') {
        $email_or_username = sanitize($_POST['email_or_username']); $password = $_POST['password'];
        if (empty($email_or_username) || empty($password)) { set_status_message('Email/Username and Password are required.', 'error');
        } else {
            $stmt = $conn->prepare("SELECT id, username, email, password_hash, role FROM users WHERE email = ? OR username = ?"); $stmt->bind_param("ss", $email_or_username, $email_or_username); $stmt->execute(); $result = $stmt->get_result();
            if ($user = $result->fetch_assoc()) {
                if (verifyPassword($password, $user['password_hash'])) { $_SESSION['user_id'] = $user['id']; $_SESSION['username'] = $user['username']; $_SESSION['user_role'] = $user['role']; $_SESSION['email'] = $user['email']; header("Location: index.php"); exit;
                } else { set_status_message('Invalid email/username or password.', 'error'); }
            } else { set_status_message('Invalid email/username or password.', 'error'); }
            $stmt->close();
        }
    } elseif ($action === 'process_payment') {
        header('Content-Type: application/json'); $response = ['success' => false, 'message' => 'An unknown error occurred.'];
        $email_payment = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL); $transaction_id_payment = trim($_POST['transaction_id']); $total_amount_payment = floatval($_POST['total_amount']); $user_id_payment = isLoggedIn() ? $_SESSION['user_id'] : null;
        if (!filter_var($email_payment, FILTER_VALIDATE_EMAIL)) { $response['message'] = 'Invalid email address for payment.'; echo json_encode($response); if($conn) $conn->close(); exit; }
        if (empty($transaction_id_payment)) { $response['message'] = 'Transaction ID is required.'; echo json_encode($response); if($conn) $conn->close(); exit; }
        if (empty($_SESSION['cart']) || $total_amount_payment <= 0) { $response['message'] = 'Your cart is empty or total is invalid.'; echo json_encode($response); if($conn) $conn->close(); exit; }
        $purchased_course_names = []; foreach ($_SESSION['cart'] as $item) { $purchased_course_names[] = $item['name']; } $courses_purchased_string = implode(', ', $purchased_course_names);
        $sql = "INSERT INTO transactions (user_id, email, transaction_id, courses_purchased, total_amount) VALUES (?, ?, ?, ?, ?)"; $stmt = $conn->prepare($sql);
        if ($stmt) {
            $stmt->bind_param("isssd", $user_id_payment, $email_payment, $transaction_id_payment, $courses_purchased_string, $total_amount_payment);
            if ($stmt->execute()) { $_SESSION['cart'] = []; $response['success'] = true; $response['message'] = 'Payment details recorded! PDF(s) will be sent to ' . htmlspecialchars($email_payment) . ' (simulated). Your order is pending confirmation.'; $response['redirect_url'] = 'index.php?view=main&payment=success'; 
            } else { $response['message'] = 'Failed to record payment details. Error: ' . $stmt->error; }
            $stmt->close();
        } else { $response['message'] = 'Database error during payment processing. Error: ' . $conn->error; }
        echo json_encode($response); if($conn) $conn->close(); exit;
    }
    elseif ($action === 'confirm_order' && isAdmin()) {
        $transaction_id_to_confirm = isset($_POST['transaction_id_to_confirm']) ? intval($_POST['transaction_id_to_confirm']) : 0;
        if ($transaction_id_to_confirm > 0) {
            $stmt = $conn->prepare("UPDATE transactions SET order_status = 'Confirmed' WHERE id = ? AND order_status = 'Pending'"); $stmt->bind_param("i", $transaction_id_to_confirm);
            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) { set_status_message('Order ID ' . $transaction_id_to_confirm . ' confirmed successfully.', 'success');
                } else { set_status_message('Order ID ' . $transaction_id_to_confirm . ' was already confirmed or not found.', 'error'); }
            } else { set_status_message('Failed to confirm order. Database error.', 'error'); }
            $stmt->close();
        } else { set_status_message('Invalid Transaction ID for confirmation.', 'error'); }
        header("Location: index.php?view=admin"); exit;
    }
    if ($conn) { $conn->close(); }
}

if (isset($_GET['action']) && $_GET['action'] === 'logout') { session_unset(); session_destroy(); header("Location: index.php"); exit; }
$current_view = $_GET['view'] ?? 'main';

// After a successful payment, process_payment action sets a GET param. We convert it to a session flash.
if(isset($_GET['payment']) && $_GET['payment'] === 'success'){
    set_status_message('Payment successful! Your order is being processed.', 'success');
    // Redirect to remove the GET param from URL, message will show from session
    header("Location: index.php?view=main");
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Online Courses</title>
    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2980b9; --secondary-color: #27ae60; --accent-color: #c0392b;
            --background-color: #ecf0f1; --text-color: #2c3e50; --card-background: #ffffff;
            --border-color: #bdc3c7; --font-family: 'Open Sans', sans-serif;
            --box-shadow: 0 5px 15px rgba(0,0,0,0.08); --box-shadow-hover: 0 8px 25px rgba(0,0,0,0.12);
            --border-radius: 8px; --transition-speed: 0.3s;
        }
        html { scroll-behavior: smooth; }
        body { font-family: var(--font-family); margin: 0; background-color: var(--background-color); color: var(--text-color); line-height: 1.7; display: flex; flex-direction: column; min-height: 100vh; font-weight: 400; }
        .container { width: 90%; max-width: 1200px; margin: 0 auto; padding: 25px 0; }
        header { background-image: linear-gradient(to right, var(--primary-color), #3498db); color: white; padding: 18px 0; box-shadow: 0 3px 8px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 1000; }
        header .container { display: flex; justify-content: space-between; align-items: center; padding-top:0; padding-bottom:0;}
        header h1 { margin: 0; font-size: 2.2em; font-weight: 300; letter-spacing: 1px;}
        header h1 a {color:white; text-decoration:none;}
        nav a, nav span { color: white; text-decoration: none; margin-left: 18px; font-size: 1em; transition: color var(--transition-speed) ease; }
        nav a:hover { color: #f1c40f; }
        nav span { font-style: normal; font-weight: 600; }
        main { flex-grow: 1; }
        .section { padding: 50px 0; }
        .section-title { text-align: center; font-size: 2.5em; margin-bottom: 40px; color: var(--primary-color); font-weight: 600; position: relative; }
        .section-title::after { content: ''; display: block; width: 80px; height: 3px; background-color: var(--secondary-color); margin: 10px auto 0; border-radius: 2px; }

        .hero-slider { width: 100%; height: 60vh; min-height: 400px; max-height: 550px; position: relative; overflow: hidden; background-color: #333; margin-bottom: 40px; }
        .hero-slide { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-size: cover; background-position: center center; opacity: 0; transition: opacity 1s ease-in-out; display: flex; align-items: center; justify-content: center; text-align: center; }
        .hero-slide.active { opacity: 1; }
        .hero-slide::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0, 0, 0, 0.5); }
        .hero-content { position: relative; z-index: 2; color: white; max-width: 700px; padding: 20px; }
        .hero-content h2 { font-size: 2.8em; margin-bottom: 15px; font-weight: 700; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
        .hero-content p { font-size: 1.2em; margin-bottom: 25px; font-weight: 300; }
        .hero-dots { position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); display: flex; z-index: 3; }
        .hero-dot { width: 12px; height: 12px; border-radius: 50%; background-color: rgba(255, 255, 255, 0.5); margin: 0 5px; cursor: pointer; transition: background-color var(--transition-speed) ease; }
        .hero-dot.active { background-color: white; }

        .course-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 30px; }
        .course-card { background-color: var(--card-background); border-radius: var(--border-radius); box-shadow: var(--box-shadow); overflow: hidden; display: flex; flex-direction: column; transition: transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease; opacity: 0; transform: translateY(30px); }
        .course-card.animate-in { opacity: 1; transform: translateY(0); }
        .course-card:hover { transform: translateY(-8px) scale(1.02); box-shadow: var(--box-shadow-hover); }
        .course-card img { width: 100%; height: 200px; object-fit: cover; background-color: #eee; border-bottom: 3px solid var(--primary-color); }
        .course-card-content { padding: 25px; flex-grow: 1; display: flex; flex-direction: column;}
        .course-card h3 { font-size: 1.4em; margin-top: 0; margin-bottom: 12px; color: var(--primary-color); font-weight:600; }
        .course-card p { font-size: 0.95em; margin-bottom: 18px; flex-grow: 1; color: #555; }
        .course-price { font-size: 1.3em; font-weight: 700; color: var(--secondary-color); margin-bottom: 18px; }
        .btn { display: inline-block; background-color: var(--primary-color); color: white !important; padding: 12px 25px; text-decoration: none; border-radius: 50px; border: none; cursor: pointer; font-size: 1em; font-weight: 600; transition: background-color var(--transition-speed) ease, transform 0.2s ease; text-align: center; text-transform: uppercase; letter-spacing: 0.5px; }
        .btn:hover { background-color: #1f648b; transform: translateY(-2px); }
        .btn-secondary { background-color: var(--secondary-color); }
        .btn-secondary:hover { background-color: #1e8449; transform: translateY(-2px); }
        .btn-accent { background-color: var(--accent-color); }
        .btn-accent:hover { background-color: #a93226; transform: translateY(-2px); }
        .btn-small { padding: 6px 12px; font-size: 0.85em; }
        .btn-success { background-color: var(--secondary-color); }
        .btn-success:hover { background-color: #27ae60; }

        .cart-page-container { background-color: #fff; padding: 30px; border-radius: var(--border-radius); box-shadow: var(--box-shadow); }
        .cart-items-list { list-style: none; padding: 0; margin: 0 0 30px 0; }
        .cart-items-list li { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #ecf0f1; }
        .cart-items-list li:last-child { border-bottom: none; }
        .cart-item-details { display: flex; align-items: center; flex-grow: 1; }
        .cart-item-details img { width: 80px; height: 50px; object-fit: cover; border-radius: 4px; margin-right: 15px; }
        .cart-item-info h4 { margin: 0 0 5px 0; font-size: 1.1em; color: var(--primary-color); }
        .cart-item-info span { font-size: 0.9em; color: #7f8c8d; }
        .cart-item-price { font-weight: 600; margin: 0 20px; }
        .cart-item-actions a { color: var(--accent-color); text-decoration: none; font-size:0.9em; }
        .cart-summary { text-align: right; margin-bottom: 30px; }
        .cart-summary p { font-size: 1.8em; font-weight: 700; color: var(--primary-color); margin:0; }
        .cart-actions { text-align: center; display: flex; justify-content: space-between; gap: 15px; flex-wrap: wrap;}

        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; color: #555; }
        .form-group input[type="email"], .form-group input[type="text"], .form-group input[type="password"] { width: 100%; padding: 14px; border: 1px solid var(--border-color); border-radius: var(--border-radius); box-sizing: border-box; font-size: 1em; transition: border-color var(--transition-speed) ease, box-shadow var(--transition-speed) ease; }
        .form-group input:focus { border-color: var(--primary-color); box-shadow: 0 0 0 3px rgba(41, 128, 185, 0.2); outline: none; }

        #payment-section { background-color: var(--card-background); padding: 35px; border-radius: var(--border-radius); box-shadow: var(--box-shadow); max-width: 800px; margin: 40px auto; }
        .payment-layout { display: flex; flex-direction: column; gap: 30px; }
        @media (min-width: 768px) { .payment-layout { flex-direction: row; align-items: flex-start; } .payment-layout > div { flex: 1; } .qr-code-column { max-width: 300px; margin-right: 30px;} }
        .qr-code-container { text-align: center; padding: 15px; border: 1px solid var(--border-color); border-radius: var(--border-radius); background-color: #f9f9f9;}
        .qr-code-container img { max-width: 220px; width:100%; height:auto; border: 1px solid var(--border-color); display:block; margin:0 auto 15px auto; }
        .qr-code-container p { font-size: 0.95em; color: #555; margin-top: 10px; line-height: 1.5; }

        #js-status-message, .php-status-message { padding: 18px; border-radius: var(--border-radius); max-width: 700px; margin: 20px auto; font-weight: 600;}
        #js-status-message.success, .php-status-message.success { background-color: #d1e7dd; color: #0f5132; border: 1px solid #badbcc; }
        #js-status-message.error, .php-status-message.error { background-color: #f8d7da; color: #842029; border: 1px solid #f5c2c7; }
        #js-status-message:empty, .php-status-message:empty { display: none; }

        .auth-form-container { max-width: 480px; margin: 50px auto; padding: 35px; background-color: var(--card-background); border-radius: var(--border-radius); box-shadow: var(--box-shadow); }
        .admin-panel table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: var(--box-shadow); }
        .admin-panel th, .admin-panel td { border: 1px solid var(--border-color); padding: 12px 15px; text-align: left; font-size:0.9em; vertical-align: middle;}
        .admin-panel th { background-color: #e9ecef; color: #495057; font-weight: 600; }
        .admin-panel tr:nth-child(even) { background-color: #f8f9fa; }
        .admin-panel .status-pending { color: var(--accent-color); font-weight: bold; background-color: #fdecea; padding: 3px 6px; border-radius: 4px;}
        .admin-panel .status-confirmed { color: var(--secondary-color); font-weight: bold; background-color: #d1e7dd; padding: 3px 6px; border-radius: 4px;}

        .fade-in-section { opacity: 0; transform: translateY(20px); transition: opacity 0.6s ease-out, transform 0.6s ease-out; }
        .fade-in-section.is-visible { opacity: 1; transform: translateY(0); }
        .hidden { display: none !important; }
        footer { background-color: #2c3e50; color: #bdc3c7; text-align: center; padding: 25px 0; font-size: 0.95em; margin-top: auto; }
        footer p { margin: 0; }

        @media (max-width: 768px) {
            header .container { flex-direction: column; text-align: center; }
            header h1 { margin-bottom: 10px; font-size: 1.8em; }
            nav { margin-top: 10px; display: flex; flex-wrap: wrap; justify-content: center;}
            nav a, nav span { margin: 5px 8px; font-size:0.9em; }
            .hero-slider { height: 45vh; min-height: 300px; }
            .hero-content h2 { font-size: 2em; } .hero-content p { font-size: 1em; }
            .section-title { font-size: 2em; }
            .course-grid { grid-template-columns: 1fr; gap: 20px;}
            .cart-items-list li { flex-direction: column; align-items: flex-start; gap: 10px;}
            .cart-item-details { width: 100%; justify-content: space-between;}
            .cart-item-price { margin-top: 5px; }
            .cart-item-actions { margin-top: 5px; align-self: flex-end; }
            .cart-actions { flex-direction: column;} .cart-actions a { margin-bottom: 10px; }
            .admin-panel th, .admin-panel td { font-size: 0.8em; padding: 8px 10px; }
            .payment-layout { flex-direction: column; }
            .qr-code-column { margin-right: 0; margin-bottom: 20px; max-width: 100%;}
        }
    </style>
</head>
<body>

    <header>
        <div class="container">
            <h1><a href="index.php">Online Course</a></h1>
            <nav>
                <a href="index.php?view=main#courses-section-anchor">Courses</a>
                <a href="index.php?view=cart">Cart (<?php echo getCartItemCount(); ?>)</a>
                <?php if (isLoggedIn()): ?>
                    <?php if (isAdmin()): ?>
                        <a href="index.php?view=admin">Admin</a>
                    <?php endif; ?>
                    <span><?php echo sanitize($_SESSION['username']); ?></span>
                    <a href="index.php?action=logout">Logout</a>
                <?php else: ?>
                    <a href="index.php?view=login">Login</a>
                    <a href="index.php?view=register">Register</a>
                <?php endif; ?>
            </nav>
        </div>
    </header>

    <main>
        <?php if ($current_view === 'main'): ?>
            <section class="hero-slider" id="hero-slider">
                <?php
                $actual_slider_courses = [];
                foreach ($slider_courses_ids as $id) if (isset($courses[$id]) && isset($courses[$id]['hero_image'])) $actual_slider_courses[] = $courses[$id];
                foreach ($actual_slider_courses as $index => $course): ?>
                <div class="hero-slide <?php echo $index === 0 ? 'active' : ''; ?>" style="background-image: url('<?php echo htmlspecialchars($course['hero_image']); ?>');">
                    <div class="hero-content">
                        <h2><?php echo htmlspecialchars($course['name']); ?></h2>
                        <p><?php echo htmlspecialchars($course['description']); ?></p>
                        <a href="#course-card-<?php echo $course['id']; ?>" class="btn btn-secondary">Explore Course</a>
                    </div>
                </div>
                <?php endforeach; ?>
                <?php if (count($actual_slider_courses) > 1): ?>
                <div class="hero-dots">
                    <?php for ($i = 0; $i < count($actual_slider_courses); $i++) echo "<span class='hero-dot ".($i===0?'active':'')."' data-slide='$i'></span>"; ?>
                </div>
                <?php endif; ?>
            </section>
        <?php endif; ?>

        <div class="container">
            <?php if (!empty($status_message)): ?>
                <div class="php-status-message <?php echo $status_type; ?>"><?php echo $status_message; ?></div>
            <?php endif; ?>
            <div id="js-status-message"></div>


            <?php if ($current_view === 'main'): ?>
                <div id="courses-section-anchor"></div>
                <section id="courses-section" class="section fade-in-section">
                    <h2 class="section-title">Our Courses</h2>
                    <div class="course-grid">
                        <?php foreach ($courses as $course): ?>
                        <div class="course-card animate-on-scroll" id="course-card-<?php echo $course['id']; ?>" data-id="<?php echo $course['id']; ?>">
                            <img src="<?php echo htmlspecialchars($course['image_url']); ?>" alt="Image for <?php echo htmlspecialchars($course['name']); ?>">
                            <div class="course-card-content">
                                <h3><?php echo htmlspecialchars($course['name']); ?></h3>
                                <p><?php echo htmlspecialchars($course['description']); ?></p>
                                <p class="course-price">₹<?php echo $course['price']; ?></p>
                                <button class="btn add-to-cart-btn" data-id="<?php echo $course['id']; ?>">Add to Cart</button>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </section>

            <?php elseif ($current_view === 'cart'): ?>
                <section id="cart-page" class="section fade-in-section">
                    <h2 class="section-title">Your Shopping Cart</h2>
                    <div class="cart-page-container">
                        <?php if (empty($_SESSION['cart'])): ?>
                            <p style="text-align:center; font-size: 1.2em;">Your cart is currently empty.</p>
                        <?php else: ?>
                            <ul class="cart-items-list">
                                <?php foreach ($_SESSION['cart'] as $item_id => $item): ?>
                                <li>
                                    <div class="cart-item-details">
                                        <img src="<?php echo htmlspecialchars($item['image_url']); ?>" alt="<?php echo htmlspecialchars($item['name']); ?>">
                                        <div class="cart-item-info">
                                            <h4><?php echo htmlspecialchars($item['name']); ?></h4>
                                            <span>Individual Course PDF</span>
                                        </div>
                                    </div>
                                    <div class="cart-item-price">₹<?php echo $item['price']; ?></div>
                                    <div class="cart-item-actions">
                                        <a href="index.php?action=remove_from_cart&course_id=<?php echo $item_id; ?>" title="Remove item">× Remove</a>
                                    </div>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                            <div class="cart-summary">
                                <p>Total: ₹<?php echo getCartTotal(); ?></p>
                            </div>
                        <?php endif; ?>
                        <div class="cart-actions">
                            <a href="index.php?view=main#courses-section-anchor" class="btn btn-accent">Continue Shopping</a>
                            <?php if (!empty($_SESSION['cart'])): ?>
                            <a href="index.php?view=payment" class="btn btn-secondary">Proceed to Payment</a>
                            <?php endif; ?>
                        </div>
                    </div>
                </section>

            <?php elseif ($current_view === 'payment'): ?>
                <section id="payment-section" class="section fade-in-section">
                    <h2 class="section-title">Payment Simulation</h2>
                     <?php if (empty($_SESSION['cart'])): ?>
                        <p style="text-align:center;">Your cart is empty. Please add courses before proceeding to payment.</p>
                        <p style="text-align:center;"><a href="index.php?view=main#courses-section-anchor" class="btn">Browse Courses</a></p>
                    <?php else: ?>
                    <p style="text-align: center; margin-bottom:30px; font-size:1.2em;">Your total amount is: <strong style="color:var(--secondary-color);">₹<?php echo getCartTotal(); ?></strong></p>
                    <div class="payment-layout">
    <div class="qr-code-column">
        <div class="qr-code-container">
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=<?php 
                echo urlencode('upi://pay?pa=vik657@axl&pn=RecipientName&am='.getCartTotal().'&cu=INR'); 
            ?>" alt="Scan to Pay via UPI">
                                <p><strong>Instructions:</strong><br>
                                1. Scan the QR code with your preferred payment application.<br>
                                2. Ensure the amount matches your cart total.<br>
                                3. After successful payment, enter your email and the Transaction ID (from your payment app) in the form.
                                </p>
                            </div>
                        </div>
                        <div class="payment-form-column">
                            <form id="payment-form-page">
                                <div class="form-group">
                                    <label for="payment_email_page">Email Address (for PDF delivery)</label>
                                    <input type="email" id="payment_email_page" name="email" required value="<?php echo isLoggedIn() && isset($_SESSION['email']) ? sanitize($_SESSION['email']) : ''; ?>">
                                </div>
                                <div class="form-group">
                                    <label for="transaction_id_page">Transaction ID</label>
                                    <input type="text" id="transaction_id_page" name="transaction_id" required>
                                </div>
                                <input type="hidden" name="total_amount" value="<?php echo getCartTotal(); ?>">
                                <button type="submit" class="btn btn-secondary" style="width:100%;">Confirm Purchase</button>
                            </form>
                        </div>
                    </div>
                    <div style="text-align:center; margin-top:30px;">
                         <a href="index.php?view=cart" class="btn btn-accent">Back to Cart</a>
                    </div>
                    <?php endif; ?>
                </section>

            <?php elseif ($current_view === 'login'): ?>
                <section class="section fade-in-section"> <div class="auth-form-container">
                    <h2>Login to Your Account</h2>
                    <form action="index.php?view=login" method="POST"> <input type="hidden" name="action" value="login"> <div class="form-group"> <label for="login_email_or_username">Email or Username</label> <input type="text" id="login_email_or_username" name="email_or_username" required> </div> <div class="form-group"> <label for="login_password">Password</label> <input type="password" id="login_password" name="password" required> </div> <button type="submit" class="btn" style="width:100%;">Login</button> </form> <p style="margin-top:15px;">Don't have an account? <a href="index.php?view=register">Register here</a></p> </div> </section>
            <?php elseif ($current_view === 'register'): ?>
                 <section class="section fade-in-section"> <div class="auth-form-container">
                    <h2>Create an Account</h2>
                    <form action="index.php?view=register" method="POST"> <input type="hidden" name="action" value="register"> <div class="form-group"> <label for="reg_username">Username</label> <input type="text" id="reg_username" name="username" required> </div> <div class="form-group"> <label for="reg_email">Email Address</label> <input type="email" id="reg_email" name="email" required> </div> <div class="form-group"> <label for="reg_password">Password (min. 6 characters)</label> <input type="password" id="reg_password" name="password" required> </div> <div class="form-group"> <label for="reg_confirm_password">Confirm Password</label> <input type="password" id="reg_confirm_password" name="confirm_password" required> </div> <button type="submit" class="btn" style="width:100%;">Register</button> </form> <p style="margin-top:15px;">Already have an account? <a href="index.php?view=login">Login here</a></p> </div> </section>
            <?php elseif ($current_view === 'admin' && isAdmin()): ?>
                <section class="section admin-panel fade-in-section"> <h2 class="section-title">Admin Panel - Manage Orders</h2>
                    <?php
                    $conn_admin = connectDB(); $stmt_admin = $conn_admin->prepare( "SELECT t.id, t.email, t.transaction_id, t.courses_purchased, t.total_amount, t.order_status, t.purchase_timestamp, u.username FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.purchase_timestamp DESC" ); $stmt_admin->execute(); $transactions_result = $stmt_admin->get_result();
                    ?> <div style="overflow-x:auto;"> <table> <thead> <tr> <th>ID</th><th>User</th><th>Email (Payer)</th><th>Trans. ID</th><th>Courses</th><th>Amount</th><th>Status</th><th>Date</th><th>Action</th> </tr> </thead> <tbody>
                    <?php if ($transactions_result->num_rows > 0): while($tx = $transactions_result->fetch_assoc()): ?>
                    <tr> <td><?php echo $tx['id']; ?></td> <td><?php echo $tx['username'] ? sanitize($tx['username']) : 'Guest'; ?></td> <td><?php echo sanitize($tx['email']); ?></td> <td><?php echo sanitize($tx['transaction_id']); ?></td> <td><?php echo sanitize($tx['courses_purchased']); ?></td> <td>₹<?php echo $tx['total_amount']; ?></td> <td> <span class="status-<?php echo strtolower(sanitize($tx['order_status'])); ?>"><?php echo sanitize($tx['order_status']); ?></span> </td> <td><?php echo date("Y-m-d H:i A", strtotime($tx['purchase_timestamp'])); ?></td> <td>
                    <?php if ($tx['order_status'] === 'Pending'): ?> <form method="POST" action="index.php?view=admin" style="display:inline;"> <input type="hidden" name="action" value="confirm_order"> <input type="hidden" name="transaction_id_to_confirm" value="<?php echo $tx['id']; ?>"> <button type="submit" class="btn btn-small btn-success">Confirm</button> </form> <?php else: ?> <span>-</span> <?php endif; ?>
                    </td> </tr> <?php endwhile; else: ?> <tr><td colspan="9">No transactions found.</td></tr> <?php endif; ?>
                    </tbody> </table> </div> <?php $stmt_admin->close(); $conn_admin->close(); ?>
                </section>
            <?php elseif ($current_view === 'admin' && !isAdmin()): ?>
                <section class="section fade-in-section"> <h2 class="section-title">Access Denied</h2> <p style="text-align:center;">You do not have permission to view the admin panel.</p> </section>
            <?php else: ?>
                 <section class="section fade-in-section"><p style="text-align:center;">Page not found or content error.</p></section>
            <?php endif; ?>
        </div>
    </main>

    <footer> <div class="container"> <p>© <?php echo date("Y"); ?> Online Course. All Rights Reserved. (Enhanced Demo)</p> </div> </footer>

    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const currentView = new URLSearchParams(window.location.search).get('view') || 'main';
        if (currentView === 'main') { initializeCoursePage(); initializeHeroSlider(); } 
        else if (currentView === 'payment') { initializePaymentPage(); }
        initializeScrollAnimations(); 
    });

    function initializeHeroSlider() { 
        const slides = document.querySelectorAll('.hero-slide'); const dots = document.querySelectorAll('.hero-dot');
        const heroDotsContainer = document.querySelector('.hero-dots');
        if (slides.length <= 1) { if (heroDotsContainer) heroDotsContainer.style.display = 'none'; return; }
        let currentSlide = 0; let slideInterval = setInterval(nextSlide, 5000); 
        function showSlide(index) {
            slides.forEach((slide, i) => { slide.classList.remove('active'); if(dots[i]) dots[i].classList.remove('active'); });
            slides[index].classList.add('active'); if(dots[index]) dots[index].classList.add('active'); currentSlide = index;
        }
        function nextSlide() { let next = (currentSlide + 1) % slides.length; showSlide(next); }
        dots.forEach(dot => {
            dot.addEventListener('click', () => { clearInterval(slideInterval); showSlide(parseInt(dot.dataset.slide)); slideInterval = setInterval(nextSlide, 7000); });
        });
    }

    function initializeScrollAnimations() { 
        const animatedElements = document.querySelectorAll('.fade-in-section, .animate-on-scroll'); if (!animatedElements.length) return;
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    if(entry.target.classList.contains('animate-on-scroll')) entry.target.classList.add('animate-in');
                    else entry.target.classList.add('is-visible');
                    // observer.unobserve(entry.target); // Uncomment to animate only once
                }
            });
        }, { threshold: 0.1 });
        animatedElements.forEach(el => observer.observe(el));
    }

    function displayJsStatusMessage(message, type = 'success', duration = 4000) { 
        const statusMessageEl = document.getElementById('js-status-message'); if (!statusMessageEl) return;
        statusMessageEl.textContent = message; statusMessageEl.className = ''; statusMessageEl.classList.add(type); statusMessageEl.style.display = 'block';
        setTimeout(() => { statusMessageEl.style.display = 'none'; }, duration);
    }
    function isValidEmail(email) { const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; return emailRegex.test(email); }

    function initializeCoursePage() {
        document.querySelectorAll('.add-to-cart-btn').forEach(button => {
            button.addEventListener('click', async (e) => {
                const courseId = e.target.dataset.id; const formData = new FormData(); formData.append('action', 'add_to_cart'); formData.append('course_id', courseId);
                try {
                    const response = await fetch('index.php', { method: 'POST', body: formData }); const result = await response.json();
                    displayJsStatusMessage(result.message, result.success ? 'success' : 'error');
                    if (result.success) { 
                        // Update cart count in header dynamically
                        const cartLink = document.querySelector('nav a[href="index.php?view=cart"]');
                        if(cartLink) cartLink.textContent = `Cart (${result.cart_count})`;
                        setTimeout(() => { window.location.href = 'index.php?view=cart'; }, 1500); // Slightly longer delay for user to see message
                    }
                } catch (error) { console.error('Error adding to cart:', error); displayJsStatusMessage('Failed to add item to cart. Network error.', 'error'); }
            });
        });
    }

    function initializePaymentPage() {
        const paymentForm = document.getElementById('payment-form-page');
        if(paymentForm) paymentForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailInput = document.getElementById('payment_email_page'); const transactionIdInput = document.getElementById('transaction_id_page'); const totalAmountInput = paymentForm.querySelector('input[name="total_amount"]');
            if (!emailInput.value || !transactionIdInput.value) { displayJsStatusMessage('Please fill in both email and transaction ID.', 'error'); return; }
            if (!isValidEmail(emailInput.value)) { displayJsStatusMessage('Please enter a valid email address.', 'error'); return; }
            const formData = new FormData(); formData.append('action', 'process_payment'); formData.append('email', emailInput.value); formData.append('transaction_id', transactionIdInput.value); formData.append('total_amount', totalAmountInput.value);
            try {
                const response = await fetch('index.php', { method: 'POST', body: formData }); const result = await response.json();
                if (result.success) { window.location.href = result.redirect_url || 'index.php?view=main&payment=success'; } 
                else { displayJsStatusMessage(result.message || 'An error occurred processing payment.', 'error'); }
            } catch (error) { console.error('Error processing payment:', error); displayJsStatusMessage('A network error occurred during payment. Please try again.', 'error'); }
        });
    }
    </script>
</body>
</html>