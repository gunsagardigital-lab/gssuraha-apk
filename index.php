<?php
declare(strict_types=1);
ini_set('expose_php','0');
ini_set('session.use_strict_mode','1');
ini_set('session.use_only_cookies','1');
// Allow a checked Remember Me session to survive browser restarts for up to 30 days.
ini_set('session.gc_maxlifetime','2592000');
$secureCookie = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') || ((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_set_cookie_params([
    'lifetime'=>0,
    'path'=>'/',
    'secure'=>$secureCookie,
    'httponly'=>true,
    'samesite'=>'Lax'
]);
session_start();
date_default_timezone_set('Asia/Kolkata');

// Baseline browser hardening. CSP is intentionally not forced here because this app
// contains required inline UI scripts/styles and QR/payment integrations.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
if ($secureCookie) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

const APP_NAME = 'GS Suraha Finance';
const DB_FILE = __DIR__ . '/data/gs_suraha.sqlite';

if (!is_dir(__DIR__ . '/data')) mkdir(__DIR__ . '/data', 0775, true);

$db = new SQLite3(DB_FILE);
$db->exec('PRAGMA foreign_keys = ON');
$db->exec('PRAGMA busy_timeout = 5000');

$db->exec("CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','staff','member')),
    member_id INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS admin_permissions(
    user_id INTEGER NOT NULL,
    capability TEXT NOT NULL,
    PRIMARY KEY(user_id, capability),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)");
$db->exec("CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NULL,
    action TEXT NOT NULL,
    details TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
)");
$userCols2=[]; $q2=$db->query("PRAGMA table_info(users)"); while($c2=$q2->fetchArray(SQLITE3_ASSOC)) $userCols2[$c2['name']]=true;
if(!isset($userCols2['is_super_admin'])) $db->exec("ALTER TABLE users ADD COLUMN is_super_admin INTEGER NOT NULL DEFAULT 0");

$db->exec("CREATE TABLE IF NOT EXISTS login_attempts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    attempted_at INTEGER NOT NULL,
    success INTEGER NOT NULL DEFAULT 0
)");


$db->exec("CREATE TABLE IF NOT EXISTS whatsapp_login_otps(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    mobile TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_sent_at INTEGER NOT NULL,
    verified_at INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_whatsapp_login_otps_user ON whatsapp_login_otps(user_id)");


// Admin/staff display name support (backward-compatible migration)
$userCols = [];
$uRes = $db->query("PRAGMA table_info(users)");
while ($col = $uRes->fetchArray(SQLITE3_ASSOC)) { $userCols[$col['name']] = true; }
if (!isset($userCols['display_name'])) { $db->exec("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''"); }

$db->exec("CREATE TABLE IF NOT EXISTS members(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    father_name TEXT DEFAULT '',
    mobile TEXT NOT NULL,
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)");

// Member KYC/document storage (backward-compatible migration for existing SQLite DBs)
$memberCols = [];
$colRes = $db->query("PRAGMA table_info(members)");
while ($col = $colRes->fetchArray(SQLITE3_ASSOC)) { $memberCols[$col['name']] = true; }
if (!isset($memberCols['document'])) { $db->exec("ALTER TABLE members ADD COLUMN document TEXT DEFAULT ''"); }
if (!isset($memberCols['father_name'])) { $db->exec("ALTER TABLE members ADD COLUMN father_name TEXT DEFAULT ''"); }
if (!isset($memberCols['signature'])) { $db->exec("ALTER TABLE members ADD COLUMN signature TEXT DEFAULT ''"); }
if (!isset($memberCols['bank_name'])) { $db->exec("ALTER TABLE members ADD COLUMN bank_name TEXT DEFAULT ''"); }
if (!isset($memberCols['account_holder'])) { $db->exec("ALTER TABLE members ADD COLUMN account_holder TEXT DEFAULT ''"); }
if (!isset($memberCols['account_number'])) { $db->exec("ALTER TABLE members ADD COLUMN account_number TEXT DEFAULT ''"); }
if (!isset($memberCols['ifsc'])) { $db->exec("ALTER TABLE members ADD COLUMN ifsc TEXT DEFAULT ''"); }
if (!isset($memberCols['bank_upi_id'])) { $db->exec("ALTER TABLE members ADD COLUMN bank_upi_id TEXT DEFAULT ''"); }
if (!isset($memberCols['photo_locked'])) {
    $db->exec("ALTER TABLE members ADD COLUMN photo_locked INTEGER NOT NULL DEFAULT 0");
    // One-time only: lock existing photos when the column is first created.
    $db->exec("UPDATE members SET photo_locked=1 WHERE COALESCE(photo,'')<>'' AND COALESCE(photo_locked,0)=0");
}
if (!isset($memberCols['signature_locked'])) {
    $db->exec("ALTER TABLE members ADD COLUMN signature_locked INTEGER NOT NULL DEFAULT 0");
    // One-time only: lock existing signatures when the column is first created.
    $db->exec("UPDATE members SET signature_locked=1 WHERE COALESCE(signature,'')<>'' AND COALESCE(signature_locked,0)=0");
}
if (!isset($memberCols['gender'])) { $db->exec("ALTER TABLE members ADD COLUMN gender TEXT DEFAULT ''"); }
if (!is_dir(__DIR__ . '/uploads/signatures')) { mkdir(__DIR__ . '/uploads/signatures', 0775, true); }
if (!is_dir(__DIR__ . '/uploads/members')) { mkdir(__DIR__ . '/uploads/members', 0775, true); }
if (!is_dir(__DIR__ . '/uploads/branding')) { mkdir(__DIR__ . '/uploads/branding', 0775, true); }

$db->exec("CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)");
$db->exec("CREATE TABLE IF NOT EXISTS whatsapp_messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NULL,
    mobile TEXT DEFAULT '',
    member_name TEXT DEFAULT '',
    direction TEXT NOT NULL DEFAULT 'outbound',
    message_type TEXT NOT NULL DEFAULT 'text',
    message_text TEXT DEFAULT '',
    status TEXT DEFAULT 'sent',
    meta_message_id TEXT DEFAULT '',
    created_by INTEGER NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    raw_payload TEXT DEFAULT ''
)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_whatsapp_messages_mobile ON whatsapp_messages(mobile)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_whatsapp_messages_created ON whatsapp_messages(created_at)");
// WhatsApp media support: keep incoming photos/documents in a private local folder.
if (!is_dir(__DIR__ . '/uploads/whatsapp_media')) { @mkdir(__DIR__ . '/uploads/whatsapp_media', 0775, true); }
foreach ([
    "ALTER TABLE whatsapp_messages ADD COLUMN media_id TEXT DEFAULT ''",
    "ALTER TABLE whatsapp_messages ADD COLUMN media_mime TEXT DEFAULT ''",
    "ALTER TABLE whatsapp_messages ADD COLUMN media_file TEXT DEFAULT ''",
    "ALTER TABLE whatsapp_messages ADD COLUMN media_name TEXT DEFAULT ''"
] as $alter) { try { @$db->exec($alter); } catch (Throwable $e) {} }

$db->exec("CREATE TABLE IF NOT EXISTS whatsapp_call_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mobile TEXT DEFAULT '',
    call_type TEXT DEFAULT '',
    call_status TEXT DEFAULT '',
    meta_call_id TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    raw_payload TEXT DEFAULT ''
)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_whatsapp_calls_created ON whatsapp_call_logs(created_at)");
$db->exec("CREATE TABLE IF NOT EXISTS activity_notice_dismissals(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    notice_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, notice_key)
)");
$db->exec("CREATE TABLE IF NOT EXISTS notices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT DEFAULT '',
    body TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
)");
$db->exec("CREATE TABLE IF NOT EXISTS staff_member_assignments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    staff_id INTEGER NOT NULL,
    member_id INTEGER NOT NULL,
    assigned_by INTEGER NULL,
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(staff_id,member_id),
    FOREIGN KEY(staff_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_by) REFERENCES users(id) ON DELETE SET NULL
)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_staff_member_assignments_staff ON staff_member_assignments(staff_id)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_staff_member_assignments_member ON staff_member_assignments(member_id)");

$db->exec("CREATE TABLE IF NOT EXISTS member_closures(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    contribution_total REAL NOT NULL DEFAULT 0,
    interest_pool REAL NOT NULL DEFAULT 0,
    member_interest REAL NOT NULL DEFAULT 0,
    deductions REAL NOT NULL DEFAULT 0,
    refund_amount REAL NOT NULL DEFAULT 0,
    reason TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Approved',
    approved_by INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(approved_by) REFERENCES users(id)
)");
$closureCols=[]; $cc=$db->query("PRAGMA table_info(member_closures)"); while($cc && ($cr=$cc->fetchArray(SQLITE3_ASSOC))) $closureCols[]=$cr['name'];
if(!in_array('requested_by',$closureCols,true)) $db->exec("ALTER TABLE member_closures ADD COLUMN requested_by INTEGER NULL");
if(!in_array('requested_at',$closureCols,true)) $db->exec("ALTER TABLE member_closures ADD COLUMN requested_at TEXT NULL");

$db->exec("CREATE TABLE IF NOT EXISTS contributions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    month TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'Online',
    status TEXT NOT NULL DEFAULT 'Pending',
    txn_id TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id)
)");
$conCols=[]; $ccr=$db->query("PRAGMA table_info(contributions)"); while($cr=$ccr->fetchArray(SQLITE3_ASSOC)) $conCols[$cr['name']]=true;
if(!isset($conCols['reject_reason'])) $db->exec("ALTER TABLE contributions ADD COLUMN reject_reason TEXT DEFAULT ''");
if(!isset($conCols['rejected_by'])) $db->exec("ALTER TABLE contributions ADD COLUMN rejected_by INTEGER NULL");
if(!isset($conCols['rejected_at'])) $db->exec("ALTER TABLE contributions ADD COLUMN rejected_at TEXT DEFAULT ''");
$db->exec("CREATE TABLE IF NOT EXISTS loan_applications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    requested REAL NOT NULL,
    tenure INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    note TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Pending',
    approved_amount REAL DEFAULT 0,
    interest_rate REAL DEFAULT 0,
    reviewed_by INTEGER NULL,
    review_note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT DEFAULT '',
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(reviewed_by) REFERENCES users(id)
)");
// Staff workflow fields for loan applications (backward-compatible migration)
$loanAppCols = [];
$laRes = $db->query("PRAGMA table_info(loan_applications)");
while ($col = $laRes->fetchArray(SQLITE3_ASSOC)) { $loanAppCols[$col['name']] = true; }
if (!isset($loanAppCols['staff_remark'])) { $db->exec("ALTER TABLE loan_applications ADD COLUMN staff_remark TEXT DEFAULT ''"); }
if (!isset($loanAppCols['staff_reviewed_by'])) { $db->exec("ALTER TABLE loan_applications ADD COLUMN staff_reviewed_by INTEGER NULL"); }
if (!isset($loanAppCols['staff_reviewed_at'])) { $db->exec("ALTER TABLE loan_applications ADD COLUMN staff_reviewed_at TEXT DEFAULT ''"); }
if (!isset($loanAppCols['forwarded_at'])) { $db->exec("ALTER TABLE loan_applications ADD COLUMN forwarded_at TEXT DEFAULT ''"); }
if (!isset($loanAppCols['assigned_staff_id'])) { $db->exec("ALTER TABLE loan_applications ADD COLUMN assigned_staff_id INTEGER NULL"); }
$db->exec("CREATE INDEX IF NOT EXISTS idx_loan_applications_assigned_staff ON loan_applications(assigned_staff_id)");
$db->exec("CREATE TABLE IF NOT EXISTS loan_application_assignment_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    loan_application_id INTEGER NOT NULL,
    old_staff_id INTEGER NULL,
    new_staff_id INTEGER NULL,
    changed_by INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
// One-time/backward-compatible assignment for existing applications: use the latest staff-member mapping.
$db->exec("UPDATE loan_applications SET assigned_staff_id=(SELECT sma.staff_id FROM staff_member_assignments sma WHERE sma.member_id=loan_applications.member_id ORDER BY sma.assigned_at DESC, sma.id DESC LIMIT 1) WHERE assigned_staff_id IS NULL AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=loan_applications.member_id)");

$db->exec("CREATE TABLE IF NOT EXISTS loans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    principal REAL NOT NULL,
    interest_rate REAL NOT NULL,
    tenure INTEGER NOT NULL,
    purpose TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS emi_schedule(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    loan_id INTEGER NOT NULL,
    installment_no INTEGER NOT NULL,
    due_date TEXT NOT NULL,
    amount REAL NOT NULL,
    paid_amount REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Pending',
    FOREIGN KEY(loan_id) REFERENCES loans(id) ON DELETE CASCADE
)");
$db->exec("CREATE TABLE IF NOT EXISTS payments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    loan_id INTEGER NULL,
    emi_id INTEGER NULL,
    amount REAL NOT NULL,
    mode TEXT NOT NULL,
    txn_id TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(loan_id) REFERENCES loans(id),
    FOREIGN KEY(emi_id) REFERENCES emi_schedule(id)
)");
// Reconcile legacy EMI/loan status so completed loans do not remain Active.
$db->exec("UPDATE emi_schedule SET status='Paid' WHERE amount>0 AND paid_amount>=amount-0.009 AND status!='Paid'");
$db->exec("UPDATE loans SET status='Closed' WHERE status='Active' AND EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id) AND NOT EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id AND MAX(e.amount-e.paid_amount,0)>0.009)");
$payCols=[]; $pcr=$db->query("PRAGMA table_info(payments)"); while($pr=$pcr->fetchArray(SQLITE3_ASSOC)) $payCols[$pr['name']]=true;
if(!isset($payCols['reject_reason'])) $db->exec("ALTER TABLE payments ADD COLUMN reject_reason TEXT DEFAULT ''");
if(!isset($payCols['rejected_by'])) $db->exec("ALTER TABLE payments ADD COLUMN rejected_by INTEGER NULL");
if(!isset($payCols['rejected_at'])) $db->exec("ALTER TABLE payments ADD COLUMN rejected_at TEXT DEFAULT ''");
$emiCols=[]; $ec=$db->query("PRAGMA table_info(emi_schedule)"); while($ec && ($er=$ec->fetchArray(SQLITE3_ASSOC))) $emiCols[$er['name']]=true;
if(!isset($emiCols['principal_component'])) $db->exec("ALTER TABLE emi_schedule ADD COLUMN principal_component REAL NOT NULL DEFAULT 0");
if(!isset($emiCols['interest_component'])) $db->exec("ALTER TABLE emi_schedule ADD COLUMN interest_component REAL NOT NULL DEFAULT 0");
if(!isset($emiCols['interest_paid'])) $db->exec("ALTER TABLE emi_schedule ADD COLUMN interest_paid REAL NOT NULL DEFAULT 0");
$db->exec("CREATE TABLE IF NOT EXISTS interest_collections(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_payment_id INTEGER UNIQUE NULL,
    loan_id INTEGER NOT NULL,
    emi_id INTEGER NOT NULL,
    interest_amount REAL NOT NULL DEFAULT 0,
    contribution_basis_total REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_payment_id) REFERENCES payments(id) ON DELETE SET NULL,
    FOREIGN KEY(loan_id) REFERENCES loans(id),
    FOREIGN KEY(emi_id) REFERENCES emi_schedule(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS member_interest_ledger(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interest_collection_id INTEGER NOT NULL,
    member_id INTEGER NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    contribution_basis REAL NOT NULL DEFAULT 0,
    total_contribution_basis REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(interest_collection_id,member_id),
    FOREIGN KEY(interest_collection_id) REFERENCES interest_collections(id) ON DELETE CASCADE,
    FOREIGN KEY(member_id) REFERENCES members(id)
)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_member_interest_ledger_member ON member_interest_ledger(member_id)");
$db->exec("CREATE TABLE IF NOT EXISTS reminder_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    emi_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(emi_id) REFERENCES emi_schedule(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS contribution_reminder_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    month TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(member_id) REFERENCES members(id)
);
");
$db->exec("CREATE TABLE IF NOT EXISTS member_notifications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NULL,
    FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
)");
$db->exec("CREATE TABLE IF NOT EXISTS notification_dismissals(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    notification_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id,notification_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(notification_id) REFERENCES member_notifications(id) ON DELETE CASCADE
)");
$db->exec("CREATE TABLE IF NOT EXISTS fund_adjustments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('Expense','Withdrawal')),
    amount REAL NOT NULL,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
)");
// Interest & refund controls: additive schema, preserving all existing records.
$db->exec("CREATE TABLE IF NOT EXISTS financial_other_income(
    id INTEGER PRIMARY KEY AUTOINCREMENT, amount REAL NOT NULL CHECK(amount>0), note TEXT NOT NULL DEFAULT '',
    income_date TEXT NOT NULL, created_by INTEGER NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS financial_year_closings(
    id INTEGER PRIMARY KEY AUTOINCREMENT, financial_year TEXT NOT NULL UNIQUE,
    interest_received REAL NOT NULL DEFAULT 0, other_income REAL NOT NULL DEFAULT 0,
    operating_expenses REAL NOT NULL DEFAULT 0, net_profit REAL NOT NULL DEFAULT 0,
    reserve_percent REAL NOT NULL DEFAULT 10, reserve_amount REAL NOT NULL DEFAULT 0,
    distributable_amount REAL NOT NULL DEFAULT 0, eligible_members INTEGER NOT NULL DEFAULT 0,
    per_member_amount REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Draft',
    approved_by INTEGER NULL, approved_at TEXT DEFAULT '', created_by INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(approved_by) REFERENCES users(id), FOREIGN KEY(created_by) REFERENCES users(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS member_dividend_allocations(
    id INTEGER PRIMARY KEY AUTOINCREMENT, closing_id INTEGER NOT NULL, financial_year TEXT NOT NULL,
    member_id INTEGER NOT NULL, amount REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Pending',
    payment_reference TEXT DEFAULT '', paid_at TEXT DEFAULT '', paid_by INTEGER NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(financial_year,member_id),
    UNIQUE(payment_reference), FOREIGN KEY(closing_id) REFERENCES financial_year_closings(id),
    FOREIGN KEY(member_id) REFERENCES members(id), FOREIGN KEY(paid_by) REFERENCES users(id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS financial_audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NULL, action TEXT NOT NULL,
    entity_type TEXT NOT NULL, entity_id INTEGER NULL, details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(actor_id) REFERENCES users(id)
)");

function seed(): void {
    global $db;
    $count = (int)$db->querySingle("SELECT COUNT(*) FROM users");
    if ($count === 0) {
        $stmt = $db->prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)");
        foreach ([['admin','Admin@123','admin'],['staff','Staff@123','staff']] as $u) {
            $stmt->bindValue(1,$u[0],SQLITE3_TEXT); $stmt->bindValue(2,password_hash($u[1],PASSWORD_DEFAULT),SQLITE3_TEXT); $stmt->bindValue(3,$u[2],SQLITE3_TEXT); $stmt->execute();
        }
    }
    if ((int)$db->querySingle("SELECT COUNT(*) FROM settings") === 0) {
        $s=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?)");
        foreach ([
            ['monthly_contribution','1000'],
            ['loan_eligibility_percent','80'],
            ['upi_id',''],
            ['upi_name','GS Suraha Sahyog Samiti'],
            ['society_name','GS Suraha Sahyog Samiti'],
            ['society_tagline','Finance Co-operative Society'], ['app_download_url',''], ['header_logo','assets/logo.png'], ['whatsapp_enabled','1'], ['whatsapp_number',''], ['whatsapp_provider','Click to Chat'], ['whatsapp_api_url',''], ['whatsapp_api_key',''], ['whatsapp_provider_mode','Meta Cloud API'], ['whatsapp_document_enabled','1'], ['sms_enabled','1'], ['sms_sender_id','GSURHA'], ['sms_provider','Manual / SMS App'], ['sms_api_url',''], ['sms_api_key',''], ['whatsapp_phone_number_id',''], ['whatsapp_graph_version','v23.0'], ['whatsapp_calling_enabled','0'], ['whatsapp_call_icon_visibility','DEFAULT'], ['whatsapp_call_callback_permission','ENABLED'], ['whatsapp_call_sip_status','DISABLED'], ['whatsapp_call_restrict_countries',''], ['whatsapp_webhook_verify_token',''], ['whatsapp_template_name','emi_reminder_hi'], ['whatsapp_template_language','hi'], ['whatsapp_welcome_template_name','member_welcome_credentials'], ['whatsapp_welcome_template_language','hi'], ['whatsapp_closure_template_name','member_closure_refund'], ['whatsapp_closure_template_language','hi'], ['payment_api_url',''], ['payment_api_key',''], ['payment_api_secret',''], ['loan_payout_provider',''], ['loan_payout_mode','Disabled until API credentials are added'], ['loan_payout_api_url',''], ['loan_payout_api_key',''], ['loan_payout_api_secret',''], ['loan_payout_account_id',''], ['loan_payout_webhook_secret',''], ['loan_payout_enabled','0'], ['sms_generic_json','1'], ['member_whatsapp_otp_enabled','1']
        ] as $x) {
            $s->bindValue(1,$x[0],SQLITE3_TEXT); $s->bindValue(2,$x[1],SQLITE3_TEXT); $s->execute();
        }
    }
    if ((int)$db->querySingle("SELECT COUNT(*) FROM members") === 0) {
        $m=$db->prepare("INSERT INTO members(code,name,mobile,email,address,status) VALUES(?,?,?,?,?,?)");
        $m->bindValue(1,'GS0001'); $m->bindValue(2,'Demo Member'); $m->bindValue(3,'9999999999'); $m->bindValue(4,'demo@example.com'); $m->bindValue(5,''); $m->bindValue(6,'Active'); $m->execute();
        $mid=(int)$db->lastInsertRowID();
        $u=$db->prepare("INSERT INTO users(username,password_hash,role,member_id) VALUES(?,?,?,?)");
        $u->bindValue(1,'GS0001'); $u->bindValue(2,password_hash('9999999999',PASSWORD_DEFAULT)); $u->bindValue(3,'member'); $u->bindValue(4,$mid); $u->execute();
        // Demo account starts with zero contribution balance.
        // Do not create a paid contribution record for the demo member.
    }
}
seed();
$firstAdminId=(int)$db->querySingle("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1");
if($firstAdminId>0 && (int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role='admin' AND is_super_admin=1")===0){ $st=$db->prepare("UPDATE users SET is_super_admin=1 WHERE id=?"); $st->bindValue(1,$firstAdminId,SQLITE3_INTEGER); $st->execute(); }

// Ensure newer installations also receive the notice setting without resetting existing data.
// WhatsApp Center defaults for existing installations.
foreach ([
    ['whatsapp_app_id',''],['whatsapp_app_secret',''],['whatsapp_config_id',''],['whatsapp_waba_id',''],['whatsapp_business_id',''],['whatsapp_embedded_signup_enabled','1'],['whatsapp_embedded_signup_version','v4'],['whatsapp_coexistence_enabled','1'],['whatsapp_session_logging_enabled','1'],['whatsapp_embedded_last_status',''],
    ['whatsapp_auto_emi_enabled','1'],['whatsapp_auto_contribution_enabled','1'],['whatsapp_auto_payment_enabled','1'],
    ['whatsapp_auto_welcome_enabled','1'],['whatsapp_auto_loan_application_enabled','0'],['whatsapp_auto_loan_approved_enabled','0'],['whatsapp_auto_loan_rejected_enabled','0'],['whatsapp_auto_loan_disbursed_enabled','0'],['whatsapp_auto_emi_paid_enabled','0'],['whatsapp_auto_refund_enabled','1'],
    ['whatsapp_template_contribution_name','contribution_received'],['whatsapp_template_contribution_language','hi'],['whatsapp_template_loan_application_name','loan_application'],['whatsapp_template_loan_application_language','hi'],['whatsapp_template_loan_approved_name','loan_approved'],['whatsapp_template_loan_approved_language','hi'],['whatsapp_template_loan_rejected_name','loan_rejected'],['whatsapp_template_loan_rejected_language','hi'],['whatsapp_template_loan_disbursed_name','loan_disbursed'],['whatsapp_template_loan_disbursed_language','hi'],['whatsapp_template_emi_paid_name','emi_payment_received'],['whatsapp_template_emi_paid_language','hi'],
    ['whatsapp_bulk_enabled','0'],['whatsapp_staff_send_enabled','1']
] as $wxDefault){
    $chk=$db->prepare("SELECT COUNT(*) FROM settings WHERE key=?"); $chk->bindValue(1,$wxDefault[0],SQLITE3_TEXT);
    if((int)$chk->execute()->fetchArray(SQLITE3_NUM)[0]===0){
        $st=$db->prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)"); $st->bindValue(1,$wxDefault[0],SQLITE3_TEXT); $st->bindValue(2,$wxDefault[1],SQLITE3_TEXT); $st->execute();
    }
}

/* V22: verification WhatsApp notifications are ON by default for existing installs.
   This only enables the verification message switches; API credentials/provider remain unchanged. */
foreach (['whatsapp_auto_contribution_enabled','whatsapp_auto_emi_paid_enabled','whatsapp_auto_loan_approved_enabled','whatsapp_auto_loan_rejected_enabled'] as $verifyWaKey) {
    $cur = (string)$db->querySingle("SELECT value FROM settings WHERE key='".SQLite3::escapeString($verifyWaKey)."' LIMIT 1");
    if ($cur === '') {
        $st=$db->prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)");
        $st->bindValue(1,$verifyWaKey,SQLITE3_TEXT); $st->bindValue(2,'1',SQLITE3_TEXT); $st->execute();
    } elseif ($cur !== '1') {
        $st=$db->prepare("UPDATE settings SET value='1' WHERE key=?");
        $st->bindValue(1,$verifyWaKey,SQLITE3_TEXT); $st->execute();
    }
}

if ((int)$db->querySingle("SELECT COUNT(*) FROM settings WHERE key='notice_text'") === 0) {
    $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?)");
    $st->bindValue(1,'notice_text',SQLITE3_TEXT);
    $st->bindValue(2,'Welcome to GS Suraha Finance. Please keep your member details and documents updated.',SQLITE3_TEXT);
    $st->execute();
}
if ((int)$db->querySingle("SELECT COUNT(*) FROM settings WHERE key='notice_move'") === 0) {
    $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?)");
    $st->bindValue(1,'notice_move',SQLITE3_TEXT);
    $st->bindValue(2,'1',SQLITE3_TEXT);
    $st->execute();
}
if ((int)$db->querySingle("SELECT COUNT(*) FROM settings WHERE key='notice_enabled'") === 0) {
    $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?)");
    $st->bindValue(1,'notice_enabled',SQLITE3_TEXT);
    $st->bindValue(2,'1',SQLITE3_TEXT);
    $st->execute();
}
if ((int)$db->querySingle("SELECT COUNT(*) FROM settings WHERE key='header_logo'") === 0) {
    $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?)");
    $st->bindValue(1,'header_logo',SQLITE3_TEXT);
    $st->bindValue(2,'assets/logo.png',SQLITE3_TEXT);
    $st->execute();
}

function h(mixed $v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }

// SQLite CURRENT_TIMESTAMP is stored in UTC. Render WhatsApp log timestamps in India time.
function whatsappLocalTime(mixed $value): string {
    $value=trim((string)$value); if($value==='') return '';
    try { return (new DateTimeImmutable($value, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Kolkata'))->format('Y-m-d H:i:s'); }
    catch(Throwable $e) { return $value; }
}

function uploadMemberFile(string $field, string $code, string $kind): string {
    if (!isset($_FILES[$field]) || !is_array($_FILES[$field]) || ($_FILES[$field]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return '';
    if (($_FILES[$field]['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed for '.$kind.'.');
    if ((int)($_FILES[$field]['size'] ?? 0) > 5 * 1024 * 1024) throw new RuntimeException($kind.' must be 5 MB or smaller.');
    $tmp=(string)$_FILES[$field]['tmp_name'];
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    $allowed = in_array($kind, ['Photo','Signature'], true)
        ? ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp']
        : ['application/pdf'=>'pdf','image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
    if (!isset($allowed[$mime])) throw new RuntimeException($kind.' format is not allowed.');
    $safe=preg_replace('/[^A-Za-z0-9_-]/','_', $code);
    $name=$safe.'_'.$kind.'_'.bin2hex(random_bytes(6)).'.'.$allowed[$mime];
    $path=__DIR__.'/uploads/members/'.$name;
    if (!move_uploaded_file($tmp,$path)) throw new RuntimeException('Could not save '.$kind.'.');
    return 'uploads/members/'.$name;
}
function makeSignatureTransparent(string $src, string $dest): bool {
    if (!function_exists('imagecreatefrompng')) return false;
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($src);
    if($mime==='image/jpeg') $im=@imagecreatefromjpeg($src);
    elseif($mime==='image/png') $im=@imagecreatefrompng($src);
    elseif($mime==='image/webp' && function_exists('imagecreatefromwebp')) $im=@imagecreatefromwebp($src);
    else return false;
    if(!$im) return false;
    $w=imagesx($im); $h=imagesy($im);
    $out=imagecreatetruecolor($w,$h);
    imagealphablending($out,false); imagesavealpha($out,true);
    $transparent=imagecolorallocatealpha($out,255,255,255,127);
    imagefilledrectangle($out,0,0,$w,$h,$transparent);
    for($y=0;$y<$h;$y++){
        for($x=0;$x<$w;$x++){
            $rgba=imagecolorsforindex($im,imagecolorat($im,$x,$y));
            $r=$rgba['red']; $g=$rgba['green']; $b=$rgba['blue']; $a=$rgba['alpha'];
            $brightness=min($r,$g,$b); $spread=max($r,$g,$b)-$brightness;
            if($a>=125 || ($r>=238 && $g>=238 && $b>=238)){
                $na=127;
            } elseif($r>=220 && $g>=220 && $b>=220 && $spread<18){
                $na=min(127,(int)((255-min($r,$g,$b))*2.2));
            } else {
                $na=max(0,min(127,$a));
            }
            $c=imagecolorallocatealpha($out,$r,$g,$b,$na);
            imagesetpixel($out,$x,$y,$c);
        }
    }
    $ok=imagepng($out,$dest,6); imagedestroy($im); imagedestroy($out); return $ok;
}
function uploadBrandLogo(string $field): string {
    if (!isset($_FILES[$field]) || !is_array($_FILES[$field]) || ($_FILES[$field]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return '';
    if (($_FILES[$field]['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) throw new RuntimeException('Logo upload failed.');
    if ((int)($_FILES[$field]['size'] ?? 0) > 3 * 1024 * 1024) throw new RuntimeException('Logo must be 3 MB or smaller.');
    $tmp=(string)$_FILES[$field]['tmp_name'];
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    $allowed=['image/png'=>'png','image/jpeg'=>'jpg','image/webp'=>'webp'];
    if (!isset($allowed[$mime])) throw new RuntimeException('Logo format is not allowed. Use PNG, JPG or WebP.');
    $name='header_logo_'.date('Ymd_His').'_'.bin2hex(random_bytes(4)).'.'.$allowed[$mime];
    $path=__DIR__.'/uploads/branding/'.$name;
    if (!move_uploaded_file($tmp,$path)) throw new RuntimeException('Could not save the logo.');
    return 'uploads/branding/'.$name;
}
function uploadSignature(string $field, string $code, string $kind): string {
    if (!isset($_FILES[$field]) || !is_array($_FILES[$field]) || ($_FILES[$field]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return '';
    if (($_FILES[$field]['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed for '.$kind.'.');
    if ((int)($_FILES[$field]['size'] ?? 0) > 2 * 1024 * 1024) throw new RuntimeException($kind.' must be 2 MB or smaller.');
    $tmp=(string)$_FILES[$field]['tmp_name'];
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    $allowed=['image/jpeg','image/png','image/webp'];
    if (!in_array($mime,$allowed,true)) throw new RuntimeException($kind.' format is not allowed. Use JPG, PNG or WebP.');
    $safe=preg_replace('/[^A-Za-z0-9_-]/','_', $code);
    $base=$safe.'_'.$kind.'_'.bin2hex(random_bytes(6));
    $path=__DIR__.'/uploads/signatures/'.$base.'.png';
    if(!makeSignatureTransparent($tmp,$path)){
        if(!move_uploaded_file($tmp,$path)) throw new RuntimeException('Could not save '.$kind.'.');
    }
    return 'uploads/signatures/'.$base.'.png';
}
function signatureFileUrl(string $path): string {
    if($path==='') return '';
    $full=__DIR__.'/'.ltrim($path,'/');
    if(is_file($full) && strtolower(pathinfo($full,PATHINFO_EXTENSION))!=='png'){
        $dest=preg_replace('/\.[^.]+$/','_transparent.png',$full);
        if($dest && (!is_file($dest) || filemtime($dest)<filemtime($full))) makeSignatureTransparent($full,$dest);
        if($dest && is_file($dest)) $path=str_replace(__DIR__.'/','',$dest);
    } elseif(is_file($full) && !str_ends_with(strtolower($full),'_transparent.png')) {
        $dest=preg_replace('/\.png$/i','_transparent.png',$full);
        if($dest && (!is_file($dest) || filemtime($dest)<filemtime($full))) makeSignatureTransparent($full,$dest);
        if($dest && is_file($dest)) $path=str_replace(__DIR__.'/','',$dest);
    }
    return h($path);
}
function memberFileUrl(string $path): string { return $path !== '' ? h($path) : ''; }
function money(float $n): string { return '₹' . number_format($n,2); }
function safeDateTimeDisplay(mixed $value,string $format='d M Y, h:i A',string $fallback='Date unavailable'): string { if(!is_scalar($value)||trim((string)$value)==='') return $fallback; $timestamp=strtotime((string)$value); return $timestamp===false?$fallback:date($format,$timestamp); }
function monthlyInstallmentDueDate(int $months,?DateTimeImmutable $anchor=null): string { $anchor=$anchor??new DateTimeImmutable('today'); $day=(int)$anchor->format('j'); $monthStart=$anchor->modify('first day of this month')->modify(($months>=0?'+':'').$months.' month'); $dueDay=min($day,(int)$monthStart->format('t')); return $monthStart->setDate((int)$monthStart->format('Y'),(int)$monthStart->format('m'),$dueDay)->format('Y-m-d'); }
function getSetting(string $key, string $default=''): string {
    global $db; $st=$db->prepare("SELECT value FROM settings WHERE key=?"); $st->bindValue(1,$key); $r=$st->execute()->fetchArray(SQLITE3_ASSOC); return $r ? (string)$r['value'] : $default;
}
function setSetting(string $key, string $value): void {
    global $db; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$key,SQLITE3_TEXT); $st->bindValue(2,$value,SQLITE3_TEXT); $st->execute();
}
function persistRememberedLogin(): void {
    if(empty($_SESSION['remember_login'])) return;
    $_SESSION['persistent_login']=true;
    $p=session_get_cookie_params();
    setcookie(session_name(),session_id(),[
        'expires'=>time()+2592000,'path'=>$p['path']?:'/',
        'secure'=>(bool)$p['secure'],'httponly'=>true,'samesite'=>$p['samesite']??'Lax'
    ]);
    unset($_SESSION['remember_login']);
}
function user(): ?array {
    // Refresh the logged-in user from SQLite so older sessions also get
    // newly-added columns such as display_name without PHP warnings.
    global $db;
    if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) {
        unset($_SESSION['user']);
        return null;
    }
    $sessionUser = $_SESSION['user'];
    $id = (int)($sessionUser['id'] ?? 0);
    if ($id > 0) {
        $st = $db->prepare("SELECT * FROM users WHERE id=?");
        $st->bindValue(1, $id, SQLITE3_INTEGER);
        $fresh = $st->execute()->fetchArray(SQLITE3_ASSOC);
        if ($fresh) {
            unset($fresh['password_hash']);
            if (!array_key_exists('display_name', $fresh)) { $fresh['display_name'] = ''; }
            $_SESSION['user'] = $fresh;
            return $fresh;
        }
    }
    unset($_SESSION['user'], $_SESSION['login_time'], $_SESSION['last_activity'], $_SESSION['csrf'], $_SESSION['persistent_login'], $_SESSION['remember_login']);
    if (session_status() === PHP_SESSION_ACTIVE) { session_regenerate_id(true); }
    return null;
}
function requireLogin(): void {
    if (!user()) { header('Location: ?route=login'); exit; }
    $timeout=!empty($_SESSION['persistent_login'])?43200:(int)getSetting('session_timeout_minutes','60'); if($timeout<5) $timeout=5;
    if (!empty($_SESSION['last_activity']) && (time() - (int)$_SESSION['last_activity'] > $timeout*60)) {
        unset($_SESSION['user'], $_SESSION['login_time'], $_SESSION['last_activity'], $_SESSION['csrf']);
        session_regenerate_id(true);
        header('Location: ?route=login&expired=1'); exit;
    }
    if (getSetting('maintenance_mode','0')==='1' && (($currentUser=user())===null || ($currentUser['role']??'')!=='admin')) {
        // Keep the admin control panel available during maintenance so an admin can
        // continue working and switch maintenance mode OFF. Staff and members are
        // still redirected to the maintenance page; normal role/capability checks
        // continue to protect admin-only routes.
        $allowed=['login','logout','maintenance'];
        global $route; if(!in_array($route,$allowed,true)){ header('Location: ?route=maintenance'); exit; }
    }
    $_SESSION['last_activity'] = time();
}
function audit(string $action,string $details=''): void { global $db; $u=user(); $st=$db->prepare("INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)"); $st->bindValue(1,$u?(int)$u['id']:null,SQLITE3_INTEGER); $st->bindValue(2,$action,SQLITE3_TEXT); $st->bindValue(3,$details,SQLITE3_TEXT); $st->execute(); }
function isSuperAdmin(?array $u=null): bool { $u=$u?:user(); return !!($u && $u['role']==='admin' && (int)($u['is_super_admin']??0)===1); }
function adminCapability(): string { global $route,$originalRoute; $r=$originalRoute??$route; $map=['admin-panel'=>'dashboard','dashboard'=>'dashboard','members'=>'members','member-edit'=>'members','member-view'=>'members','member-excel'=>'members','admin-member-photo'=>'members','admin-member-mobile'=>'members','admin-member-address'=>'members','contributions'=>'contributions','contribution-reminders'=>'reminders','emi-reminders'=>'reminders','loan-applications'=>'loans','loans'=>'loans','emi-payments'=>'payments','reports'=>'reports','reports-excel'=>'reports','report-pdf'=>'reports','settings'=>'settings','communications'=>'communications','meta-connection'=>'whatsapp-sms-center','sms-settings'=>'whatsapp-sms-center','fund-adjustments'=>'funds','backup'=>'backup','admin-users'=>'admins','staff-member-users'=>'users','notifications'=>'notifications','whatsapp-center'=>'whatsapp-center','whatsapp-sms-center'=>'whatsapp-sms-center','whatsapp-settings'=>'whatsapp-sms-center','whatsapp-bulk'=>'whatsapp-center','whatsapp-payment'=>'whatsapp-center','whatsapp-chat-logs'=>'whatsapp-center','whatsapp-calling-logs'=>'whatsapp-sms-center']; if($r==='whatsapp-center'){ $tab=(string)($_GET['tab']??'home'); return ['bulk'=>'whatsapp-center','payment'=>'whatsapp-center','logs'=>'whatsapp-center','calls'=>'whatsapp-sms-center','meta'=>'whatsapp-sms-center'][$tab] ?? 'whatsapp-center'; } return $map[$r] ?? ''; }
function canAdmin(string $cap): bool { $u=user(); if(!$u || $u['role']!=='admin') return false; if(isSuperAdmin($u)) return true; global $db; $st=$db->prepare("SELECT 1 FROM admin_permissions WHERE user_id=? AND capability=?"); $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$cap,SQLITE3_TEXT); return !!$st->execute()->fetchArray(SQLITE3_NUM); }
function showAdminNav(string $cap): bool { $u=user(); return !!($u && $u['role']==='admin' && canAdmin($cap)); }
function canStaff(string $cap): bool { $u=user(); if(!$u || $u['role']!=='staff') return false; global $db; $count=(int)$db->querySingle('SELECT COUNT(*) FROM admin_permissions WHERE user_id='.(int)$u['id']); if($count===0) return true; $st=$db->prepare('SELECT 1 FROM admin_permissions WHERE user_id=? AND capability=?'); $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$cap,SQLITE3_TEXT); return !!$st->execute()->fetchArray(SQLITE3_NUM); }
function showNav(string $cap): bool { $u=user(); if(!$u) return false; if($u['role']==='admin') return canAdmin($cap); if($u['role']==='staff') return canStaff($cap); return true; }
function requireRole(array $roles): void { requireLogin(); $u=user(); if (!in_array($u['role'],$roles,true)) { http_response_code(403); exit('Access denied'); } $cap=adminCapability(); if($u['role']==='admin' && !isSuperAdmin($u) && $cap!=='' && !canAdmin($cap)){ http_response_code(403); exit('Admin permission required'); } if($u['role']==='staff' && $cap!=='' && !canStaff($cap)){ http_response_code(403); exit('Staff permission required'); } }
function requireMemberOwner(int $memberId): void {
    $u=user();
    if (!$u || $u['role'] !== 'member' || (int)($u['member_id'] ?? 0) !== $memberId) {
        http_response_code(403); exit('Access denied');
    }
}
function noticeFeed(): array {
    global $db; $u=user();
    $items=[];
    $role=(string)($u['role']??'');
    $memberId=(int)($u['member_id']??0);
    $userId=(int)($u['id']??0);

    // 1) Managed notices (admin-created) — visible to everyone when enabled
    $nr=$db->query("SELECT id,title,body,created_at FROM notices WHERE enabled=1 ORDER BY id DESC");
    while($n=$nr->fetchArray(SQLITE3_ASSOC)){
        $txt=trim((string)$n['title'])!=='' ? '📢 '.trim((string)$n['title']).' — '.trim((string)$n['body']) : '📢 '.trim((string)$n['body']);
        $items[]=['text'=>$txt,'href'=>'#','created_at'=>(string)$n['created_at'],'notice_id'=>(int)$n['id'],'notice_type'=>'managed','id'=>(int)$n['id'],'title'=>(string)$n['title']];
    }

    $add=function(string $text,string $href,string $created,int $id=0,string $title='') use (&$items): void {
        $items[]=['text'=>$text,'href'=>$href,'created_at'=>$created,'id'=>$id,'title'=>$title];
    };

    $isStaffAdmin=in_array($role,['admin','staff'],true);

    // ---- ADMIN / STAFF activity notices ----
    if($isStaffAdmin){
        // Pending member closures (admin only)
        if($role==='admin'){
            $r=$db->query("SELECT mc.id,mc.member_id,mc.created_at,m.name,m.code FROM member_closures mc JOIN members m ON m.id=mc.member_id WHERE mc.status='Pending' ORDER BY mc.id DESC LIMIT 12");
            while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))){
                $add('🔒 '.($x['name']??'Member').' ('.($x['code']??'').') ने Member ID बंद / refund request भेजी है — Admin approval required.','?route=member-close&id='.(int)$x['member_id'],(string)$x['created_at'],(int)$x['id'],'Member closure request');
            }
        }

        // Staff: only assigned members' contributions; Admin: all
        if($role==='staff'){
            $r=$db->query("SELECT c.id,c.amount,c.status,c.month,c.created_at,m.name,m.code
                FROM contributions c JOIN members m ON m.id=c.member_id
                JOIN staff_member_assignments sma ON sma.member_id=c.member_id AND sma.staff_id=".(int)$userId."
                ORDER BY c.id DESC LIMIT 12");
        } else {
            $r=$db->query("SELECT c.id,c.amount,c.status,c.month,c.created_at,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id ORDER BY c.id DESC LIMIT 12");
        }
        while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Pending');
            $title=$status==='Pending'?'Contribution verification pending':($status==='Paid'?'Contribution payment verified':'Contribution payment rejected');
            $detail='💰 '.($x['name']??'Member').' ('.($x['code']??'').') ने '.money((float)$x['amount']).' contribution payment किया — Status: '.$status;
            $add($detail,'?route=contributions&focus='.(int)$x['id'],(string)$x['created_at'],(int)$x['id'],$title);
        }

        // EMI/loan payments
        if($role==='staff'){
            $r=$db->query("SELECT p.id,p.amount,p.status,p.mode,p.created_at,m.name,m.code,e.installment_no
                FROM payments p JOIN members m ON m.id=p.member_id
                LEFT JOIN emi_schedule e ON e.id=p.emi_id
                JOIN staff_member_assignments sma ON sma.member_id=p.member_id AND sma.staff_id=".(int)$userId."
                ORDER BY p.id DESC LIMIT 12");
        } else {
            $r=$db->query("SELECT p.id,p.amount,p.status,p.mode,p.created_at,m.name,m.code,e.installment_no FROM payments p JOIN members m ON m.id=p.member_id LEFT JOIN emi_schedule e ON e.id=p.emi_id ORDER BY p.id DESC LIMIT 12");
        }
        while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))) {
            $emi=$x['installment_no']!==null ? ' EMI #'.(int)$x['installment_no'] : ' payment';
            $status=(string)($x['status']??'Pending');
            $title=$status==='Pending'?'EMI payment verification pending':(($status==='Paid'||$status==='Approved')?'EMI payment verified':'EMI payment rejected');
            $detail='💳 '.($x['name']??'Member').' ('.($x['code']??'').') ने '.money((float)$x['amount']).$emi.' किया — Status: '.$status;
            $add($detail,'?route=emi-payments&focus='.(int)$x['id'],(string)$x['created_at'],(int)$x['id'],$title);
        }

        // Loan applications (staff scoped to assigned)
        $loanAppScope=$role==='staff' ? 'WHERE la.assigned_staff_id='.(int)$userId : '';
        $r=$db->query("SELECT la.id,la.requested,la.status,la.created_at,m.name,m.code FROM loan_applications la JOIN members m ON m.id=la.member_id $loanAppScope ORDER BY la.id DESC LIMIT 12");
        while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Pending');
            $title=$status==='Pending'?'Loan application verification pending':($status==='Forwarded'?'Loan application forwarded to Admin':($status==='Approved'?'Loan application approved':'Loan application rejected'));
            $detail='📝 '.($x['name']??'Member').' ('.($x['code']??'').') ने '.money((float)$x['requested']).' का loan apply किया — Status: '.$status;
            $add($detail,'?route=loan-applications&focus='.(int)$x['id'],(string)$x['created_at'],(int)$x['id'],$title);
        }

        // Disbursed / loan records
        if($role==='staff'){
            $r=$db->query("SELECT l.id,l.principal,l.status,l.created_at,m.name,m.code FROM loans l JOIN members m ON m.id=l.member_id JOIN staff_member_assignments sma ON sma.member_id=l.member_id AND sma.staff_id=".(int)$userId." ORDER BY l.id DESC LIMIT 12");
        } else {
            $r=$db->query("SELECT l.id,l.principal,l.status,l.created_at,m.name,m.code FROM loans l JOIN members m ON m.id=l.member_id ORDER BY l.id DESC LIMIT 12");
        }
        while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Active');
            $add('🏦 '.($x['name']??'Member').' ('.($x['code']??'').') का '.money((float)$x['principal']).' loan record बना — Status: '.$status,'?route=loans&focus='.(int)$x['id'],(string)$x['created_at'],(int)$x['id'],'Loan record');
        }

        // EMI due in next 7 days (staff: assigned members only)
        $localToday=date('Y-m-d'); $localWeek=date('Y-m-d',strtotime('+7 days'));
        if($role==='staff'){
            $r=$db->query("SELECT e.amount,e.paid_amount,e.due_date,l.id loan_id,m.name,m.code
                FROM emi_schedule e JOIN loans l ON l.id=e.loan_id JOIN members m ON m.id=l.member_id
                JOIN staff_member_assignments sma ON sma.member_id=l.member_id AND sma.staff_id=".(int)$userId."
                WHERE COALESCE(e.status,'')!='Paid'
                  AND (COALESCE(e.amount,0)-COALESCE(e.paid_amount,0))>0
                  AND e.due_date>='{$localToday}' AND e.due_date<='{$localWeek}'
                ORDER BY date(e.due_date) ASC, e.id ASC LIMIT 12");
        } else {
            $r=$db->query("SELECT e.amount,e.paid_amount,e.due_date,l.id loan_id,m.name,m.code
                FROM emi_schedule e JOIN loans l ON l.id=e.loan_id JOIN members m ON m.id=l.member_id
                WHERE COALESCE(e.status,'')!='Paid'
                  AND (COALESCE(e.amount,0)-COALESCE(e.paid_amount,0))>0
                  AND e.due_date>='{$localToday}' AND e.due_date<='{$localWeek}'
                ORDER BY date(e.due_date) ASC, e.id ASC LIMIT 12");
        }
        while($r && ($x=$r->fetchArray(SQLITE3_ASSOC))) {
            $out=max(0,(float)$x['amount']-(float)$x['paid_amount']);
            $daysLeft=max(0,(int)floor((strtotime((string)$x['due_date'])-strtotime(date('Y-m-d')))/86400));
            $when=$daysLeft===0 ? 'आज due' : $daysLeft.' दिन बाद due';
            $add('⏳ '.($x['name']??'Member').' ('.($x['code']??'').') की EMI '.$when.' है — बाकी '.money($out).' · Due: '.date('d-m-Y',strtotime((string)$x['due_date'])), '?route=emi-reminders&days=7', (string)$x['due_date']);
        }
    }

    // ---- MEMBER: only own activity + managed notices already added ----
    if($role==='member' && $memberId>0){
        // Own pending contributions
        $r=$db->prepare("SELECT c.id,c.amount,c.status,c.month,c.created_at FROM contributions c WHERE c.member_id=? ORDER BY c.id DESC LIMIT 8");
        $r->bindValue(1,$memberId,SQLITE3_INTEGER);
        $res=$r->execute();
        while($res && ($x=$res->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Pending');
            if($status==='Pending'){
                $add('💰 आपका contribution '.money((float)$x['amount']).' verification के लिए Pending है ('.h((string)($x['month']??'')).')','?route=member-payment-history',(string)$x['created_at'],(int)$x['id'],'Your contribution pending');
            } elseif($status==='Paid'){
                $add('✅ आपका contribution '.money((float)$x['amount']).' verify हो गया','?route=member-payment-history',(string)$x['created_at'],(int)$x['id'],'Your contribution paid');
            }
        }
        // Own EMI payments pending/paid (last few)
        $r=$db->prepare("SELECT p.id,p.amount,p.status,p.created_at,e.installment_no FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id WHERE p.member_id=? ORDER BY p.id DESC LIMIT 8");
        $r->bindValue(1,$memberId,SQLITE3_INTEGER);
        $res=$r->execute();
        while($res && ($x=$res->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Pending');
            $emi=$x['installment_no']!==null ? ' EMI #'.(int)$x['installment_no'] : '';
            if($status==='Pending'){
                $add('💳 आपका'.$emi.' payment '.money((float)$x['amount']).' verification Pending है','?route=member-emi-pay',(string)$x['created_at'],(int)$x['id'],'Your EMI payment pending');
            }
        }
        // Own loan application status
        $r=$db->prepare("SELECT la.id,la.requested,la.status,la.created_at FROM loan_applications la WHERE la.member_id=? ORDER BY la.id DESC LIMIT 5");
        $r->bindValue(1,$memberId,SQLITE3_INTEGER);
        $res=$r->execute();
        while($res && ($x=$res->fetchArray(SQLITE3_ASSOC))) {
            $status=(string)($x['status']??'Pending');
            $add('📝 आपका loan आवेदन '.money((float)$x['requested']).' — Status: '.$status,'?route=member-loan-apply',(string)$x['created_at'],(int)$x['id'],'Your loan application');
        }
        // Own EMI due in next 7 days
        $localToday=date('Y-m-d'); $localWeek=date('Y-m-d',strtotime('+7 days'));
        $r=$db->prepare("SELECT e.amount,e.paid_amount,e.due_date,e.id
            FROM emi_schedule e JOIN loans l ON l.id=e.loan_id
            WHERE l.member_id=? AND COALESCE(e.status,'')!='Paid'
              AND (COALESCE(e.amount,0)-COALESCE(e.paid_amount,0))>0
              AND e.due_date>=? AND e.due_date<=?
            ORDER BY date(e.due_date) ASC LIMIT 8");
        $r->bindValue(1,$memberId,SQLITE3_INTEGER);
        $r->bindValue(2,$localToday,SQLITE3_TEXT);
        $r->bindValue(3,$localWeek,SQLITE3_TEXT);
        $res=$r->execute();
        while($res && ($x=$res->fetchArray(SQLITE3_ASSOC))) {
            $out=max(0,(float)$x['amount']-(float)$x['paid_amount']);
            $daysLeft=max(0,(int)floor((strtotime((string)$x['due_date'])-strtotime(date('Y-m-d')))/86400));
            $when=$daysLeft===0 ? 'आज due' : $daysLeft.' दिन बाद due';
            $add('⏳ आपकी EMI '.$when.' है — बाकी '.money($out).' · Due: '.date('d-m-Y',strtotime((string)$x['due_date'])),'?route=member-emi-pay',(string)$x['due_date'],(int)$x['id'],'Your EMI due');
        }
    }

    // Apply per-user dismissals (managed notices cannot be dismissed from ticker)
    if($u){
        $kept=[];
        foreach($items as $it){
            if(!empty($it['notice_type']) && $it['notice_type']==='managed'){
                $kept[]=$it; continue;
            }
            if(!empty($it['custom'])){ $kept[]=$it; continue; }
            $href=(string)($it['href']??'');
            $itemId=(int)($it['id']??0);
            if($itemId>0 && strpos($href,'route=loan-applications')!==false) $key='loan|'.$itemId;
            elseif($itemId>0 && strpos($href,'route=contributions')!==false) $key='contribution|'.$itemId;
            elseif($itemId>0 && strpos($href,'route=member-payment-history')!==false) $key='contribution|'.$itemId;
            elseif($itemId>0 && (strpos($href,'route=emi-payments')!==false || strpos($href,'route=member-emi-pay')!==false)) $key=(strpos($href,'route=emi-payments')!==false?'payment|':'emi|').$itemId;
            elseif($itemId>0 && strpos($href,'route=loans')!==false) $key='loan-record|'.$itemId;
            elseif($itemId>0 && strpos($href,'route=member-close')!==false) $key='closure|'.$itemId;
            elseif($itemId>0 && strpos($href,'route=member-loan-apply')!==false) $key='loan|'.$itemId;
            else $key=$href.'|'.$itemId.'|'.(string)($it['title']??'');
            $it['notice_key']=$key;
            $st=$db->prepare("SELECT 1 FROM activity_notice_dismissals WHERE user_id=? AND notice_key=? LIMIT 1");
            $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$key,SQLITE3_TEXT);
            if(!$st->execute()->fetchArray(SQLITE3_NUM)) $kept[]=$it;
        }
        $items=$kept;
    }

    $managed=array_values(array_filter($items,fn($it)=>!empty($it['notice_type']) && $it['notice_type']==='managed'));
    $activity=array_values(array_filter($items,fn($it)=>empty($it['notice_type']) || $it['notice_type']!=='managed'));
    usort($managed,fn($a,$b)=>strcmp((string)$b['created_at'],(string)$a['created_at']));
    usort($activity,fn($a,$b)=>strcmp((string)$b['created_at'],(string)$a['created_at']));
    return array_merge($managed,$activity);
}
function csrf(): string { if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(16)); return $_SESSION['csrf']; }
function checkCsrf(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', (string)$_POST['csrf'])) {
        http_response_code(403); exit('Invalid request token');
    }
}
function redirect(string $route): never { header('Location: ?route='.urlencode($route)); exit; }
function memberOfUser(): ?array {
    global $db; if (!user() || !user()['member_id']) return null;
    $st=$db->prepare("SELECT * FROM members WHERE id=?"); $st->bindValue(1,(int)user()['member_id']); $r=$st->execute()->fetchArray(SQLITE3_ASSOC); return $r ?: null;
}
function deleteMemberCascade(int $memberId): array {
    global $db;
    if($memberId<=0) return [false,'Invalid member.'];
    $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$memberId,SQLITE3_INTEGER);
    $member=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$member) return [false,'Member not found.'];
    try{
        $db->exec('BEGIN IMMEDIATE');
        // Remove all known member-linked records before deleting the member itself.
        foreach([
            'notification_dismissals'=>'notification_id IN (SELECT id FROM member_notifications WHERE member_id='.(int)$memberId.')',
            'reminder_logs'=>'member_id='.(int)$memberId,
            'contribution_reminder_logs'=>'member_id='.(int)$memberId,
            'payments'=>'member_id='.(int)$memberId,
            'contributions'=>'member_id='.(int)$memberId,
            'loan_applications'=>'member_id='.(int)$memberId,
            'member_closures'=>'member_id='.(int)$memberId,
            'member_notifications'=>'member_id='.(int)$memberId,
            'whatsapp_messages'=>'member_id='.(int)$memberId,
        ] as $table=>$where){ $db->exec('DELETE FROM '.$table.' WHERE '.$where); }
        $loanIds=[]; $lr=$db->query('SELECT id FROM loans WHERE member_id='.(int)$memberId); while($x=$lr->fetchArray(SQLITE3_ASSOC)) $loanIds[]=(int)$x['id'];
        foreach($loanIds as $lid){ $db->exec('DELETE FROM payments WHERE loan_id='.$lid); $db->exec('DELETE FROM emi_schedule WHERE loan_id='.$lid); }
        $db->exec('DELETE FROM loans WHERE member_id='.(int)$memberId);
        $db->exec('DELETE FROM users WHERE member_id='.(int)$memberId);
        $db->exec('DELETE FROM members WHERE id='.(int)$memberId);
        if($db->changes()<1) throw new RuntimeException('Member could not be deleted.');
        $db->exec('COMMIT');
        foreach(['photo','document','signature'] as $f){ if(!empty($member[$f])) { $fp=__DIR__.'/'.ltrim($member[$f],'/'); if(is_file($fp)) @unlink($fp); } }
        return [true,'Member '.($member['code']??'').' deleted successfully.'];
    }catch(Throwable $e){ try{$db->exec('ROLLBACK');}catch(Throwable $ignore){} return [false,'Delete failed: '.$e->getMessage()]; }
}
function emi(float $p,float $annual,int $months): float {
    if($months<=0) return 0; $r=$annual/12/100;
    if($r==0) return round($p/$months,2);
    return round($p*$r*pow(1+$r,$months)/(pow(1+$r,$months)-1),2);
}
function loanAmortizationRows(float $principal,float $annualRate,int $months): array {
    if($principal<=0||$months<1)return [];$balance=round($principal,2);$rate=$annualRate/12/100;$payment=emi($principal,$annualRate,$months);$rows=[];
    for($i=1;$i<=$months;$i++){
        $interest=$rate>0?round($balance*$rate,2):0.0;$interest=min($interest,$payment);$principalPart=round(min($balance,max(0,$payment-$interest)),2);$amount=round($principalPart+$interest,2);
        if($i===$months&&$balance-$principalPart>0.009){$principalPart=$balance;$amount=round($principalPart+$interest,2);}
        $rows[]=['amount'=>$amount,'principal_component'=>$principalPart,'interest_component'=>$interest];$balance=round(max(0,$balance-$principalPart),2);
    }
    return $rows;
}
function allocateLoanInterestToMembers(int $paymentId,int $loanId,int $emiId,float $amount,string $asOf=''): void {
    global $db;if($amount<0.005)return;
    $exists=$db->prepare("SELECT id FROM interest_collections WHERE source_payment_id=?");$exists->bindValue(1,$paymentId,SQLITE3_INTEGER);if($exists->execute()->fetchArray(SQLITE3_ASSOC))return;
    $basisSql="SELECT m.id,COALESCE(SUM(c.amount),0) basis FROM members m JOIN contributions c ON c.member_id=m.id AND c.status='Paid' WHERE m.status='Active'";
    if($asOf!=='')$basisSql.=" AND datetime(c.created_at)<=datetime('".SQLite3::escapeString($asOf)."')";
    $basisSql.=' GROUP BY m.id HAVING basis>0 ORDER BY m.id';$basisRes=$db->query($basisSql);$members=[];$total=0.0;while($basisRes&&($r=$basisRes->fetchArray(SQLITE3_ASSOC))){$r['basis']=(float)$r['basis'];$members[]=$r;$total+=$r['basis'];}
    $st=$db->prepare("INSERT INTO interest_collections(source_payment_id,loan_id,emi_id,interest_amount,contribution_basis_total,created_at) VALUES(?,?,?,?,?,COALESCE(NULLIF(?,''),CURRENT_TIMESTAMP))");$st->bindValue(1,$paymentId,SQLITE3_INTEGER);$st->bindValue(2,$loanId,SQLITE3_INTEGER);$st->bindValue(3,$emiId,SQLITE3_INTEGER);$st->bindValue(4,round($amount,2),SQLITE3_FLOAT);$st->bindValue(5,$total,SQLITE3_FLOAT);$st->bindValue(6,$asOf,SQLITE3_TEXT);if(!$st->execute())throw new RuntimeException('Could not record collected loan interest.');$collectionId=(int)$db->lastInsertRowID();
    if($total<=0||!$members)return;
    $cents=(int)round($amount*100);$allocated=0;$shares=[];
    foreach($members as $m){$exact=$cents*((float)$m['basis'])/$total;$floor=(int)floor($exact);$shares[]=['id'=>(int)$m['id'],'basis'=>(float)$m['basis'],'cents'=>$floor,'remainder'=>$exact-$floor];$allocated+=$floor;}
    usort($shares,fn($a,$b)=>($b['remainder']<=>$a['remainder'])?:($a['id']<=>$b['id']));for($i=0;$i<$cents-$allocated&&$i<count($shares);$i++)$shares[$i]['cents']++;
    foreach($shares as $sh){if($sh['cents']<=0)continue;$ins=$db->prepare("INSERT OR IGNORE INTO member_interest_ledger(interest_collection_id,member_id,amount,contribution_basis,total_contribution_basis,created_at) VALUES(?,?,?,?,?,COALESCE(NULLIF(?,''),CURRENT_TIMESTAMP))");$ins->bindValue(1,$collectionId,SQLITE3_INTEGER);$ins->bindValue(2,$sh['id'],SQLITE3_INTEGER);$ins->bindValue(3,$sh['cents']/100,SQLITE3_FLOAT);$ins->bindValue(4,$sh['basis'],SQLITE3_FLOAT);$ins->bindValue(5,$total,SQLITE3_FLOAT);$ins->bindValue(6,$asOf,SQLITE3_TEXT);if(!$ins->execute())throw new RuntimeException('Could not allocate loan interest to member.');}
}
function recordVerifiedEmiInterest(array $payment): void {
    global $db;$paymentId=(int)($payment['id']??0);$emiId=(int)($payment['emi_id']??0);$loanId=(int)($payment['loan_id']??0);if(!$paymentId||!$emiId||!$loanId)return;
    $q=$db->prepare("SELECT amount,paid_amount,interest_component,interest_paid FROM emi_schedule WHERE id=? AND loan_id=?");$q->bindValue(1,$emiId,SQLITE3_INTEGER);$q->bindValue(2,$loanId,SQLITE3_INTEGER);$e=$q->execute()->fetchArray(SQLITE3_ASSOC);if(!$e)return;
    $available=max(0,(float)$e['amount']-(float)$e['paid_amount']);$applied=min(max(0,(float)$payment['amount']),$available);$interest=max(0,(float)$e['interest_component']-(float)$e['interest_paid']);$earned=round(min($applied,$interest),2);if($earned<0.005)return;
    $u=$db->prepare("UPDATE emi_schedule SET interest_paid=MIN(interest_component,interest_paid+?) WHERE id=?");$u->bindValue(1,$earned,SQLITE3_FLOAT);$u->bindValue(2,$emiId,SQLITE3_INTEGER);if(!$u->execute())throw new RuntimeException('Could not update EMI interest ledger.');
    allocateLoanInterestToMembers($paymentId,$loanId,$emiId,$earned,'');
}
function initializeMemberInterestLedger(): void {
    global $db;
    $loans=$db->query("SELECT id,principal,interest_rate FROM loans WHERE EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id) ORDER BY id");
    while($loan=$loans->fetchArray(SQLITE3_ASSOC)){
        $q=$db->query("SELECT id,amount,interest_component,principal_component FROM emi_schedule WHERE loan_id=".(int)$loan['id']." ORDER BY installment_no");$rows=[];$needs=false;while($e=$q->fetchArray(SQLITE3_ASSOC)){$rows[]=$e;if(abs((float)$e['interest_component'])<0.00001&&((float)$loan['interest_rate'])>0)$needs=true;}
        if(!$needs)continue;$balance=(float)$loan['principal'];$rate=(float)$loan['interest_rate']/12/100;
        foreach($rows as $e){$amt=(float)$e['amount'];$interest=$rate>0?min($amt,round($balance*$rate,2)):0.0;$principal=round(min($balance,max(0,$amt-$interest)),2);$u=$db->prepare("UPDATE emi_schedule SET interest_component=?,principal_component=?,interest_paid=MIN(?,paid_amount) WHERE id=?");$u->bindValue(1,$interest,SQLITE3_FLOAT);$u->bindValue(2,$principal,SQLITE3_FLOAT);$u->bindValue(3,$interest,SQLITE3_FLOAT);$u->bindValue(4,(int)$e['id'],SQLITE3_INTEGER);$u->execute();$balance=max(0,$balance-$principal);}
    }
    if(getSetting('member_interest_ledger_backfill_v1','')==='1')return;
    $db->exec('BEGIN');try{
        $db->exec("UPDATE emi_schedule SET interest_paid=0");$db->exec("DELETE FROM member_interest_ledger");$db->exec("DELETE FROM interest_collections");$progress=[];$interestProgress=[];
        $q=$db->query("SELECT p.id,p.loan_id,p.emi_id,p.amount,p.created_at,e.amount schedule_amount,e.interest_component FROM payments p JOIN emi_schedule e ON e.id=p.emi_id WHERE p.status='Paid' AND p.emi_id IS NOT NULL ORDER BY p.created_at,p.id");
        while($p=$q->fetchArray(SQLITE3_ASSOC)){$eid=(int)$p['emi_id'];$prior=(float)($progress[$eid]??0);$applied=min(max(0,(float)$p['amount']),max(0,(float)$p['schedule_amount']-$prior));$progress[$eid]=$prior+$applied;$interestRemaining=max(0,(float)$p['interest_component']-(float)($interestProgress[$eid]??0));$earned=round(min($applied,$interestRemaining),2);$interestProgress[$eid]=(float)($interestProgress[$eid]??0)+$earned;if($earned<=0)continue;$u=$db->prepare("UPDATE emi_schedule SET interest_paid=MIN(interest_component,interest_paid+?) WHERE id=?");$u->bindValue(1,$earned,SQLITE3_FLOAT);$u->bindValue(2,$eid,SQLITE3_INTEGER);$u->execute();allocateLoanInterestToMembers((int)$p['id'],(int)$p['loan_id'],$eid,$earned,(string)$p['created_at']);}
        setSetting('member_interest_ledger_backfill_v1','1');$db->exec('COMMIT');
    }catch(Throwable $e){$db->exec('ROLLBACK');error_log('Interest ledger initialization failed: '.$e->getMessage());}
}

// Repair legacy/older loans that were created without an EMI schedule.
// This runs safely because it only creates a schedule when that loan has none.
function repairMissingEmiSchedules(): int {
    global $db;
    $created = 0;
    $loans = $db->query("SELECT l.id,l.principal,l.interest_rate,l.tenure,l.created_at FROM loans l WHERE COALESCE(l.status,'Active')='Active' AND l.tenure>0 AND NOT EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=l.id)");
    while($loan=$loans->fetchArray(SQLITE3_ASSOC)){
        $p=(float)$loan['principal']; $rate=(float)$loan['interest_rate']; $n=(int)$loan['tenure'];
        if($p<=0 || $n<1 || $n>120) continue;
        $schedule=loanAmortizationRows($p,$rate,$n);
        $base=!empty($loan['created_at']) ? strtotime((string)$loan['created_at']) : time();
        if(!$base) $base=time();
        $db->exec('BEGIN');
        try{
            foreach($schedule as $idx=>$part){
                $i=$idx+1;$due=date('Y-m-d',strtotime("+$i month",$base));
                $st=$db->prepare("INSERT INTO emi_schedule(loan_id,installment_no,due_date,amount,principal_component,interest_component) VALUES(?,?,?,?,?,?)");
                $st->bindValue(1,(int)$loan['id'],SQLITE3_INTEGER);$st->bindValue(2,$i,SQLITE3_INTEGER);$st->bindValue(3,$due,SQLITE3_TEXT);
                $st->bindValue(4,$part['amount'],SQLITE3_FLOAT);$st->bindValue(5,$part['principal_component'],SQLITE3_FLOAT);$st->bindValue(6,$part['interest_component'],SQLITE3_FLOAT);
                if(!$st->execute()) throw new RuntimeException('EMI schedule insert failed');$created++;
            }
            $db->exec('COMMIT');
        }catch(Throwable $e){
            $db->exec('ROLLBACK');
        }
    }
    return $created;
}
function notificationCount(): int {
    global $db; $u=user(); if(!$u) return 0; $count=0;
    if($u['role']==='staff') {
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Pending' AND assigned_staff_id=".(int)$u['id']);
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM contributions WHERE status='Pending'");
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM payments WHERE status='Pending'");
    } elseif($u['role']==='admin') {
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Forwarded'");
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM contributions WHERE status='Pending'");
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM payments WHERE status='Pending'");
    } else {
        $mid=(int)($u['member_id']??0);
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM loan_applications la WHERE la.member_id=$mid AND status='Pending'");
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM payments WHERE member_id=$mid AND status='Pending'");
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE l.member_id=$mid AND e.status!='Paid' AND e.due_date<=date('now')");
        $uid=(int)$u['id'];
        $count += (int)$db->querySingle("SELECT COUNT(*) FROM member_notifications n WHERE (n.member_id=$mid OR n.member_id IS NULL) AND NOT EXISTS (SELECT 1 FROM notification_dismissals d WHERE d.notification_id=n.id AND d.user_id=$uid)");
    }
    return $count;
}

function siteBaseUrl(): string {
    $https = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') || ((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $scheme = $https ? 'https' : 'http';
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    $script = str_replace('\\','/',dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')));
    $script = rtrim($script, '/.');
    return $scheme.'://'.$host.($script && $script !== '/' ? $script : '');
}
function memberVerifyUrl(string $code): string {
    return siteBaseUrl().'/?route=verify-member&code='.rawurlencode($code);
}

function upiLink(float $amount,string $txn=''): string {
    $id=getSetting('upi_id'); $name=getSetting('upi_name','GS Suraha');
    // Keep the reference short, stable and unique. Google Pay and some bank
    // apps reject a collect/deep-link request that has no transaction ref.
    $reference=trim($txn) !== '' ? trim($txn) : 'GSS'.date('YmdHis');
    $reference=preg_replace('/[^A-Za-z0-9._-]/','',$reference) ?: 'GSS'.date('YmdHis');
    return 'upi://pay?pa='.rawurlencode($id).'&pn='.rawurlencode($name).'&tr='.rawurlencode($reference).'&am='.number_format($amount,2,'.','').'&cu=INR&tn='.rawurlencode('GS Suraha payment '.$reference);
}
function upiExternalIntentLink(float $amount,string $txn=''): string {
    // Android intent URI forces the system / app wrapper to open an external UPI app
    // (PhonePe, GPay, Paytm, BHIM) instead of handling payment inside the WebView.
    // QR codes must continue using the plain upi:// URI from upiLink().
    $upi=upiLink($amount,$txn);
    $payload=substr($upi,strlen('upi://'));
    $fallback=rawurlencode(siteBaseUrl().'/?route=member-pay');
    return 'intent://'.$payload.'#Intent;scheme=upi;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;S.browser_fallback_url='.$fallback.';end';
}
function upiPlainLink(float $amount,string $txn=''): string {
    return upiLink($amount,$txn);
}
function paymentReminderLink(string $type, float $amount, int $memberId, int $emiId=0, string $month='', string $txn=''): string {
    $gateway=trim((string)getSetting('payment_api_url'));
    if($gateway!==''){
        $params=['amount'=>number_format($amount,2,'.',''),'member_id'=>(string)$memberId,'type'=>$type];
        if($emiId>0) $params['emi_id']=(string)$emiId;
        if($month!=='') $params['month']=$month;
        $params['return_url']=siteBaseUrl().'?route=payment-api-callback';
        return $gateway.'?'.http_build_query($params,'','&',PHP_QUERY_RFC3986);
    }
    if(trim((string)getSetting('upi_id'))!=='') return upiLink($amount,$txn);
    return '';
}
function hindiReminderText(array $r, float $out, string $paymentLink=''): string {
    $name=(string)$r['name']; $emi=(string)$r['installment_no']; $date=date('d-m-Y',strtotime((string)$r['due_date']));
    $overdue=((string)$r['due_date'] < date('Y-m-d'));
    $soc=getSetting('society_name','GS Suraha Sahyog Samiti');
    $text="🔔 *EMI Payment Reminder*\n\nनमस्कार {$name} जी, 🙏\n\nआपकी EMI की राशि *₹".number_format($out,2)."* ".($overdue?'बकाया है।':'दिनांक '.$date.' को जमा होनी है।')."\n\n👤 Member ID: *".(string)($r['code']??'')."*\n💳 EMI: *#{$emi}*\n📅 Due Date: *{$date}*\n💰 Amount: *₹".number_format($out,2)."*\n\nकृपया समय पर भुगतान करें।";
    if($paymentLink!=='') $text.="\n\n🔗 Payment Link: {$paymentLink}";
    return $text."\n\nधन्यवाद 🙏\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
}
function contributionReminderText(array $r, string $paymentLink=''): string {
    $name=(string)$r['name']; $amount=(float)($r['monthly_due']??0); $month=date('F Y',strtotime((string)$r['month'].'-01'));
    $soc=getSetting('society_name','GS Suraha Sahyog Samiti');
    $code=(string)($r['code']??'');
    $text="🔔 *Contribution Payment Reminder*\n\nनमस्कार {$name} जी, 🙏\n\n{$month} का मासिक योगदान अभी जमा होना बाकी है।\n\n👤 Member ID: *{$code}*\n💰 Due Amount: *₹".number_format($amount,2)."*\n📅 Month: *{$month}*\n\nकृपया समय पर अपना योगदान जमा करें।";
    if($paymentLink!=='') $text.="\n\n🔗 Payment Link: {$paymentLink}";
    return $text."\n\nधन्यवाद 🙏\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
}
function whatsappAutoTextForEvent(array $m,string $event,array $data=[]): string {
    $name=(string)($m['name']??'Member'); $code=(string)($m['code']??''); $soc=getSetting('society_name','GS Suraha Sahyog Samiti');
    $amount=(string)($data['amount']??''); $txn=(string)($data['txn']??'');
    $lines=["नमस्कार {$name} जी, 🙏","","{$soc}"];
    switch($event){
      case 'contribution': return "✅ *Contribution Received*\n\nनमस्कार {$name} जी, 🙏\n\nआपका मासिक योगदान सफलतापूर्वक प्राप्त हो गया है।\n\n👤 Member ID: *{$code}*\n💰 Amount: *₹{$amount}*\n🧾 Transaction ID: *{$txn}*\n\nधन्यवाद 🙏\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
      case 'contribution_rejected': return "❌ *Contribution Payment Rejected*\n\nनमस्कार {$name} जी, 🙏\n\nआपका Contribution Payment इस बार स्वीकार नहीं किया जा सका।\n\n👤 Member ID: *{$code}*\n💰 Amount: *₹{$amount}*\n📝 Reason: *".(string)($data['reason']??'कृपया कार्यालय से संपर्क करें।')."*\n\nकृपया सही विवरण/भुगतान के लिए समिति कार्यालय से संपर्क करें।\n\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
      case 'emi_rejected': return "❌ *EMI Payment Rejected*\n\nनमस्कार {$name} जी, 🙏\n\nआपकी EMI Payment इस बार स्वीकार नहीं की जा सकी।\n\n👤 Member ID: *{$code}*\n💳 Amount: *₹{$amount}*\n📝 Reason: *".(string)($data['reason']??'कृपया कार्यालय से संपर्क करें।')."*\n\nकृपया सही विवरण/भुगतान के लिए समिति कार्यालय से संपर्क करें।\n\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
      case 'emi_paid': return "✅ *EMI Payment Received*\n\nनमस्कार {$name} जी, 🙏\n\nआपकी EMI Payment सफलतापूर्वक प्राप्त हो गई है।\n\n👤 Member ID: *{$code}*\n💳 Amount: *₹{$amount}*\n🧾 Transaction ID: *{$txn}*\n\nधन्यवाद 🙏\n*{$soc}*";
      case 'loan_application': return "📝 *Loan Application Received*\n\nनमस्कार {$name} जी, 🙏\n\nआपका Loan Application सफलतापूर्वक प्राप्त हो गया है।\n\n👤 Member ID: *{$code}*\n💰 Requested Amount: *₹{$amount}*\n📌 Purpose: *".(string)($data['purpose']??'—')."*\n\nहमारी टीम आपके आवेदन की समीक्षा करेगी।\n\n*{$soc}*";
      case 'loan_approved': return "🎉 *Loan Approved*\n\nनमस्कार {$name} जी, 🙏\n\nआपका Loan Application स्वीकृत हो गया है।\n\n👤 Member ID: *{$code}*\n💰 Approved Amount: *₹{$amount}*\n🔢 Loan ID: *".(string)($data['loan_id']??'')."*\n\nधन्यवाद 🙏\n*{$soc}*";
      case 'loan_rejected': return "❌ *Loan Application Update*\n\nनमस्कार {$name} जी,\n\nआपका Loan Application इस समय स्वीकृत नहीं किया जा सका।\n\n👤 Member ID: *{$code}*\n💰 Requested Amount: *₹{$amount}*\n📝 Reason: *".(string)($data['reason']??'कृपया कार्यालय से संपर्क करें।')."*\n\n*{$soc}*";
      case 'loan_disbursed': return "🏦 *Loan Disbursed / Created*\n\nनमस्कार {$name} जी, 🙏\n\nआपका Loan सफलतापूर्वक create/disburse हो गया है।\n\n👤 Member ID: *{$code}*\n💰 Loan Amount: *₹{$amount}*\n🔢 Loan ID: *".(string)($data['loan_id']??'')."*\n\nआप अपनी EMI details Member Dashboard में देख सकते हैं।\n\n*{$soc}*";
      case 'closure': return "🔔 *Member Closure & Refund Update*\n\nनमस्कार {$name} जी, 🙏\n\nआपका Member Closure/Refund request approve हो गया है।\n\n👤 Member ID: *{$code}*\n💰 Final Refund: *₹{$amount}*\n\nधन्यवाद 🙏\n*{$soc}*\n_आपकी बचत, हमारा विश्वास_";
    }
    return implode('\n',$lines);
}

function sendGenericSmsApi(string $mobile,string $message): array {
    $url=trim((string)getSetting('sms_api_url')); $key=trim((string)getSetting('sms_api_key'));
    if($url==='') return [false,'SMS API URL is not configured.'];
    $payload=['to'=>$mobile,'message'=>$message,'sender_id'=>getSetting('sms_sender_id','GSURHA')];
    $ch=curl_init($url);
    curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>15,CURLOPT_HTTPHEADER=>array_filter(['Content-Type: application/json',$key?'Authorization: Bearer '.$key:null]),CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE)]);
    $body=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($err) return [false,'SMS API error: '.$err];
    if($code<200 || $code>=300) return [false,'SMS API returned HTTP '.$code.'.'];
    return [true,'SMS sent successfully.'];
}

function paymentSlipUrl(string $type,int $id): string {
    return siteBaseUrl().'/?route=payment-receipt&type='.rawurlencode($type).'&id='.$id;
}
function createPaymentSlipPdf(string $memberName,string $memberCode,string $mobile,float $amount,string $type,string $txn,string $createdAt,int $id): array {
    $dir=__DIR__.'/uploads/payment-slips';
    if(!is_dir($dir) && !mkdir($dir,0775,true) && !is_dir($dir)) return [false,'Unable to create payment slip folder.',''];
    $filename='payment-slip-'.($type==='emi'?'EMI':'Contribution').'-'.$id.'-'.bin2hex(random_bytes(5)).'.pdf';
    $path=$dir.'/'.$filename;
    try {
        /*
         * Keep the generated PDF visually aligned with the SAME receipt used by
         * ?route=payment-receipt.  This is intentionally a small self-contained
         * PDF renderer so it works on shared hosting without GD/Dompdf/Imagick.
         * The page uses the same card width, colours, spacing and content order.
         */
        $W=595; $H=842; $objects=[];
        $objects[]="<< /Type /Catalog /Pages 2 0 R >>";
        $objects[]="<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
        $objects[]="<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {$W} {$H}] /Resources << /Font << /F1 4 0 R >> /XObject << /Im1 5 0 R >> >> /Contents 6 0 R >>";
        $objects[]="<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
        $logoPath=__DIR__.'/assets/logo_pdf.jpg';
        $logoData=is_file($logoPath)?file_get_contents($logoPath):'';
        if($logoData!==''){
            [$lw,$lh]=getimagesize($logoPath);
            $objects[]="<< /Type /XObject /Subtype /Image /Width ".(int)$lw." /Height ".(int)$lh." /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length ".strlen($logoData)." /Filter /DCTDecode >>\nstream\n".$logoData."\nendstream";
        } else {
            $objects[]="<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length 3 /Filter /DCTDecode >>\nstream\n"."\xFF\xD8\xFF"."\nendstream";
        }
        $esc=function($v){$v=(string)$v; return str_replace(['\\','(',')'],['\\\\','\\(','\\)'],$v);};
        $text=function($size,$x,$y,$txt,$bold=false)use($esc){$font=$bold?'F1':'F1'; return "BT\n/{$font} {$size} Tf\n1 0 0 1 {$x} {$y} Tm\n(".$esc($txt).") Tj\nET\n";};
        $rect=function($r,$g,$b,$x,$y,$w,$h){return "q\n{$r} {$g} {$b} rg\n{$x} {$y} {$w} {$h} re f\nQ\n";};
        $line=function($r,$g,$b,$x1,$y1,$x2,$y2,$lw=1){return "q\n{$r} {$g} {$b} RG\n{$lw} w\n{$x1} {$y1} m {$x2} {$y2} l S\nQ\n";};
        $content='';
        // Page background + receipt card, matching .receipt-page / .payment-receipt.
        $content.=$rect(0.969,0.969,0.984,0,0,$W,$H);
        $content.=$rect(1,1,1,48,80,499,682);
        // Receipt header: orange -> white -> green bands, with green bottom border.
        $hx=110; $hy=520; $hw=375; $hh=92;
        $steps=48;
        for($i=0;$i<$steps;$i++){
            $t=$i/($steps-1);
            if($t<0.5){$u=$t/0.5;$r=1.0;$g=0.61+0.39*$u;$b=0.18+0.82*$u;}
            else {$u=($t-0.5)/0.5;$r=1.0-0.82*$u;$g=1.0-0.35*$u;$b=1.0-0.69*$u;}
            $content.=$rect(round($r,3),round($g,3),round($b,3),$hx+$i*($hw/$steps),$hy,$hw/$steps+0.5,$hh);
        }
        $content.=$rect(0.075,0.54,0.13,$hx,$hy-5,$hw,5);
        // Logo and header text.
        if($logoData!=='') $content.="q\n66 0 0 66 125 533 cm\n/Im1 Do\nQ\n";
        $content.=$text(7,202,595,'PAYMENT RECEIPT / BHUGTAN RASID');
        $content.=$text(18,202,572,'GS Suraha Sahyog Samiti');
        $content.=$text(9,202,557,'Finance Co-operative Society');
        // Verified strip.
        $content.=$rect(0.91,0.98,0.94,129,474,435,38);
        $content.=$text(10,225,489,'PAYMENT VERIFIED - PAID');
        // Title block.
        $safeType=$type==='emi'?'EMI Payment':'Contribution Payment';
        $content.=$text(21,129,444,$safeType);
        $content.=$text(8,129,425,'PAYMENT RECEIPT / भुगतान रसीद');
        if($type==='emi') $content.=$text(8,129,411,'EMI Payment'); else $content.=$text(8,129,411,'Contribution Payment');
        // Details — same single-column order as the website receipt.
        $y=388;
        $rows=[
            ['MEMBER NAME',$memberName],
            ['MEMBER ID',$memberCode],
            ['MOBILE',$mobile],
            ['DATE & TIME',$createdAt],
            ['PAYMENT MODE',$type==='emi'?'Online UPI':'Contribution'],
            ['REFERENCE NO.',$txn],
            ['STATUS','Paid']
        ];
        foreach($rows as [$lab,$val]){
            $content.=$text(7,129,$y,$lab);
            $content.=$text(11,129,$y-15,$val);
            $content.=$line(0.91,0.93,0.95,129,$y-24,565,$y-24,0.5);
            $y-=43;
        }
        // Amount card.
        $content.=$rect(0.957,0.973,0.992,129,151,435,55);
        $content.=$text(9,145,177,'Amount Paid / भुगतान राशि');
        $content.=$text(22,414,174,'INR '.number_format($amount,2));
        // Note and footer.
        $content.=$rect(0.973,0.984,1,129,91,435,45);
        $content.=$rect(0.31,0.56,0.91,129,91,3,45);
        $content.=$text(7,145,119,'This is a computer-generated payment receipt. Please keep it for your records.');
        $content.=$text(7,145,105,'Thank you. Please keep this receipt safely.');
        $content.=$rect(0.949,0.961,0.98,110,58,475,34);
        $content.=$text(7,214,72,'GS Suraha Sahyog Samiti - Secure - Transparent - Together');
        $content.=$line(0.85,0.88,0.92,48,80,547,80,1);
        $objects[]="<< /Length ".strlen($content)." >>\nstream\n".$content."endstream";
        $pdf="%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"; $offsets=[0];
        foreach($objects as $i=>$obj){$offsets[$i+1]=strlen($pdf);$pdf.=($i+1)." 0 obj\n".$obj."\nendobj\n";}
        $xref=strlen($pdf); $pdf.="xref\n0 ".(count($objects)+1)."\n0000000000 65535 f \n";
        for($i=1;$i<=count($objects);$i++) $pdf.=sprintf('%010d 00000 n ',$offsets[$i])."\n";
        $pdf.="trailer\n<< /Size ".(count($objects)+1)." /Root 1 0 R >>\nstartxref\n".$xref."\n%%EOF\n";
        if(file_put_contents($path,$pdf,LOCK_EX)===false) return [false,'Unable to save payment slip PDF.',''];
        if(substr($pdf,0,5)!=='%PDF-' || strpos($pdf,'%%EOF')===false) return [false,'Generated PDF is invalid.',''];
    } catch(Throwable $e){ return [false,'PDF creation failed: '.$e->getMessage(),'']; }
    return [true,'PDF created','uploads/payment-slips/'.$filename];
}

function sendWhatsAppPaymentSlip(string $mobile,string $memberName,float $amount,string $type,int $id,string $memberCode='',string $txn='',string $createdAt='',string $existingPdfRel=''): array {
    if(getSetting('whatsapp_enabled','1')!=='1') return [false,'WhatsApp sending is disabled.',''];
    if(getSetting('whatsapp_document_enabled','1')!=='1') return [false,'WhatsApp PDF document sending is disabled in settings.',''];
    $digits=preg_replace('/\D+/','',$mobile); if(strlen($digits)===10)$digits='91'.$digits;
    if($digits==='') return [false,'Member WhatsApp/mobile number is missing.',''];
    if($existingPdfRel!==''){
        $pdfRel=ltrim($existingPdfRel,'/');
        $pdfPath=__DIR__.'/'.$pdfRel;
        if(!is_file($pdfPath)) return [false,'Uploaded PDF was not found on server.',''];
        $pdfOk=true; $pdfMsg='PDF ready';
    } else {
        [$pdfOk,$pdfMsg,$pdfRel]=createPaymentSlipPdf($memberName,$memberCode,$mobile,$amount,$type,$txn,$createdAt,$id);
        if(!$pdfOk) return [false,$pdfMsg,''];
    }
    $pdfUrl=siteBaseUrl().'/'.ltrim($pdfRel,'/');
    $caption="नमस्कार {$memberName} जी, 🙏\nGS सुराहा सहयोग समिति की ओर से आपका भुगतान सफलतापूर्वक प्राप्त हो गया है।\nभुगतान राशि: ₹".number_format($amount,2)."\nभुगतान प्रकार: ".($type==='emi'?'ईएमआई भुगतान':'मासिक योगदान')."\nरेफरेंस नंबर: {$txn}\nआपकी भुगतान रसीद PDF इस संदेश के साथ संलग्न है।\nधन्यवाद।\nGS सुराहा सहयोग समिति";
    $mode=strtolower(trim((string)getSetting('whatsapp_provider_mode','Meta Cloud API')));
    if(strpos($mode,'meta')!==false || strpos($mode,'business')!==false){
        $token=trim((string)getSetting('whatsapp_api_key')); $phoneId=trim((string)getSetting('whatsapp_phone_number_id'));
        // Meta Cloud API must use the PHONE NUMBER ID in the Graph URL. Do not reuse
        // a stale/custom API URL here because it is commonly configured with a WABA ID/App ID.
        $phoneId=preg_replace('/\D+/','',$phoneId);
        $graphVersion=trim((string)getSetting('whatsapp_graph_version','v23.0'));
        if($graphVersion==='') $graphVersion='v23.0';
        if($graphVersion[0]!=='v') $graphVersion='v'.$graphVersion;
        $api=$phoneId ? 'https://graph.facebook.com/'.rawurlencode($graphVersion).'/'.$phoneId.'/messages' : '';
        if($token==='' || $phoneId==='') return [false,'Meta WhatsApp सेटिंग में सही WhatsApp Phone Number ID और Access Token भरें। PDF बन गई है, लेकिन भेजी नहीं गई।',$pdfRel];
        if(!function_exists('curl_init')) return [false,'PHP cURL extension आवश्यक है। PDF बन गई है, लेकिन भेजी नहीं गई।',$pdfRel];
        $payload=['messaging_product'=>'whatsapp','to'=>$digits,'type'=>'document','document'=>['link'=>$pdfUrl,'caption'=>$caption,'filename'=>'GS-Suraha-Payment-Slip-'.$id.'.pdf']];
        $ch=curl_init($api); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_TIMEOUT=>30]);
        $resp=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        if($err || $code<200 || $code>=300){
            $detail=trim((string)$resp);
            $hint='';
            if(stripos($detail,'does not exist')!==false || stripos($detail,'missing permissions')!==false || stripos($detail,'cannot be loaded')!==false){
                $hint=' Meta में दिया गया Phone Number ID गलत है या इस Access Token को उस नंबर की permission नहीं है। WABA ID/App ID नहीं, WhatsApp Manager में दिखने वाला Phone Number ID डालें।';
            }
            return [false,'Meta WhatsApp PDF failed'.($code?' (HTTP '.$code.')':'').($err?': '.$err:'').($detail?' — '.substr(strip_tags($detail),0,360):'').$hint,$pdfRel];
        }
        return [true,'Payment slip PDF attached and sent through Meta WhatsApp API.',$pdfRel];
    }
    $api=trim((string)getSetting('whatsapp_api_url')); $key=trim((string)getSetting('whatsapp_api_key'));
    if($api==='') return [false,'WhatsApp provider API URL is not configured. PDF was created but not sent.',$pdfRel];
    if(!function_exists('curl_init')) return [false,'PHP cURL extension is required for WhatsApp API. PDF was created.',$pdfRel];
    $payload=['to'=>$digits,'phone'=>$digits,'message'=>$caption,'document_url'=>$pdfUrl,'slip_url'=>$pdfUrl,'document'=>['url'=>$pdfUrl,'filename'=>'GS-Suraha-Payment-Slip-'.$id.'.pdf','mime_type'=>'application/pdf'],'amount'=>number_format($amount,2,'.',''),'type'=>$type];
    $headers=['Content-Type: application/json']; if($key!=='') $headers[]='Authorization: Bearer '.$key;
    $ch=curl_init($api); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_TIMEOUT=>30]);
    $resp=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($err || $code<200 || $code>=300) return [false,'WhatsApp provider PDF failed'.($code?' (HTTP '.$code.')':'').($err?': '.$err:'').(trim((string)$resp)?' — '.substr(strip_tags((string)$resp),0,240):''),$pdfRel];
    return [true,'Payment slip PDF attached and sent through WhatsApp provider API.',$pdfRel];
}
function memberContactDigits(string $mobile): string {
    $digits=preg_replace('/\D+/','',$mobile);
    if(str_starts_with($digits,'0') && strlen($digits)===11) $digits='91'.substr($digits,1);
    if(strlen($digits)===10) $digits='91'.$digits;
    return $digits;
}
function memberWhatsAppHref(string $mobile,string $message=''): string {
    $digits=memberContactDigits($mobile);
    if($digits==='') return '';
    return 'https://wa.me/'.$digits.($message!==''?'?text='.rawurlencode($message):'');
}
function memberTelHref(string $mobile): string {
    $digits=memberContactDigits($mobile);
    return $digits!=='' ? 'tel:+'.$digits : '';
}
function memberContactMessage(array $m): string {
    $name=(string)($m['name']??'Member');
    return "नमस्कार {$name} जी, 🙏\nGS सुराहा सहयोग समिति से संपर्क करने के लिए यह WhatsApp संदेश है।";
}

function sendWhatsAppMeta(string $mobile, string $message, string $emiName='', string $amount='', string $due=''): array {
    // This function also writes successful sends to the WhatsApp chat log.
    // Explicitly import the shared database handle: without this, a successful
    // Meta API response can be followed by a fatal error and HTTP 500.
    global $db;
    $token=getSetting('whatsapp_api_key'); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id')); $graphVersion=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($graphVersion==='')$graphVersion='v23.0'; if($graphVersion[0]!=='v')$graphVersion='v'.$graphVersion; $url=$phoneId ? 'https://graph.facebook.com/'.rawurlencode($graphVersion).'/'.$phoneId.'/messages' : '';
    if($token==='' || $url==='') return [false,'WhatsApp API credentials are not configured.'];
    if(!function_exists('curl_init')) return [false,'PHP cURL extension is required for WhatsApp API.'];
    $digits=preg_replace('/\D+/','',$mobile); if(strlen($digits)===10)$digits='91'.$digits;
    $payload=['messaging_product'=>'whatsapp','to'=>$digits,'type'=>'text','text'=>['preview_url'=>false,'body'=>$message]];
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE),CURLOPT_TIMEOUT=>20]);
    $resp=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($err || $code<200 || $code>=300) return [false,'WhatsApp API failed'.($code?' (HTTP '.$code.')':'').($err?': '.$err:'')];
    // Meta's successful HTTP response contains the wamid used for webhook updates.
    $responseJson=json_decode((string)$resp,true);
    $metaId=(string)($responseJson['messages'][0]['id']??'');
    $memberId=null; $memberName=$digits;
    $last10=strlen($digits)>=10?substr($digits,-10):$digits;
    // Sending success must not turn into a 500 just because optional chat logging fails.
    try {
        if($last10!=='' && $db instanceof SQLite3){
            $members=$db->query("SELECT id,name,mobile FROM members");
            if($members){
                while($mr=$members->fetchArray(SQLITE3_ASSOC)){
                    $memberDigits=preg_replace('/\D+/','',(string)($mr['mobile']??''));
                    $memberLast10=strlen($memberDigits)>=10?substr($memberDigits,-10):$memberDigits;
                    if($memberLast10===$last10){$memberId=(int)$mr['id'];$memberName=(string)($mr['name']?:$digits);break;}
                }
            }
        }
        whatsappLogMessage($digits,$memberName,'outbound','text',$message,'sent',$metaId,$memberId,(string)$resp);
    } catch (Throwable $logError) {
        error_log('GS Suraha WhatsApp send succeeded but chat logging failed: '.$logError->getMessage());
    }
    return [true,'WhatsApp API accepted the message.'];
}

function whatsappLogMessage(string $mobile,string $memberName,string $direction,string $type,string $message,string $status,string $metaId='',?int $memberId=null,string $raw='',string $mediaId='',string $mediaMime='',string $mediaFile='',string $mediaName=''): void {
    global $db; $st=$db->prepare("INSERT INTO whatsapp_messages(member_id,mobile,member_name,direction,message_type,message_text,status,meta_message_id,created_by,raw_payload,media_id,media_mime,media_file,media_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    $u=user();
    $vals=[$memberId?:null,$mobile,$memberName,$direction,$type,$message,$status,$metaId,$u?(int)$u['id']:null,$raw,$mediaId,$mediaMime,$mediaFile,$mediaName];
    foreach($vals as $i=>$v){ $st->bindValue($i+1,$v, $v===null?SQLITE3_NULL:SQLITE3_TEXT); }
    $st->execute();
}

function whatsappDownloadMedia(string $mediaId,string $mime,string $originalName=''): array {
    if($mediaId==='') return [false,'',''];
    $token=trim((string)getSetting('whatsapp_api_key','')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id',''));
    $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
    if($token===''||$phoneId==='') return [false,'',''];
    $ch=curl_init('https://graph.facebook.com/'.rawurlencode($gv).'/'.rawurlencode($mediaId));
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token],CURLOPT_TIMEOUT=>30]);
    $meta=curl_exec($ch); $ce=curl_error($ch); curl_close($ch); if($ce||!$meta)return [false,'',''];
    $j=json_decode((string)$meta,true); $url=(string)($j['url']??''); $realMime=(string)($j['mime_type']??$mime); if($url==='')return [false,'',''];
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token],CURLOPT_TIMEOUT=>60]); $bytes=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($ce||$code<200||$code>=300||$bytes===false)return [false,'',''];
    $ext='bin'; $map=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','image/gif'=>'gif','video/mp4'=>'mp4','audio/ogg'=>'ogg','audio/mpeg'=>'mp3','application/pdf'=>'pdf']; if(isset($map[$realMime]))$ext=$map[$realMime];
    $safe=preg_replace('/[^A-Za-z0-9._-]+/','_',pathinfo($originalName,PATHINFO_FILENAME)); if($safe==='')$safe='whatsapp'; $file=$mediaId.'_'.substr($safe,0,60).'.'.$ext; $rel='uploads/whatsapp_media/'.$file; $path=__DIR__.'/'.$rel;
    if(@file_put_contents($path,$bytes,LOCK_EX)===false)return [false,'',''];
    return [true,$rel,$realMime];
}

function whatsappSendTemplateToMember(array $m,string $templateName,string $language,array $parameters): array {
    $mobile=(string)($m['mobile']??''); $name=(string)($m['name']??'Member'); $mid=(int)($m['id']??0); $digits=memberContactDigits($mobile);
    if($digits==='') return [false,'Member mobile number is missing.'];
    if(getSetting('whatsapp_enabled','1')!=='1') return [false,'WhatsApp sending is disabled.'];
    $mode=strtolower(trim((string)getSetting('whatsapp_provider_mode','Meta Cloud API')));
    if(strpos($mode,'meta')!==false || strpos($mode,'business')!==false){
        $token=trim((string)getSetting('whatsapp_api_key')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id'));
        $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
        if($token===''||$phoneId==='') return [false,'Meta Access Token और Phone Number ID configure करें।'];
        if($templateName==='') return [false,'Approved WhatsApp template name configure करें।'];
        if(!function_exists('curl_init')) return [false,'PHP cURL extension आवश्यक है।'];
        $url='https://graph.facebook.com/'.rawurlencode($gv).'/'.$phoneId.'/messages';
        $params=[]; foreach($parameters as $v) $params[]=['type'=>'text','text'=>(string)$v];
        $payload=['messaging_product'=>'whatsapp','to'=>$digits,'type'=>'template','template'=>['name'=>$templateName,'language'=>['code'=>$language ?: 'hi'],'components'=>[['type'=>'body','parameters'=>$params]]]];
        $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_TIMEOUT=>30]);
        $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        if($ce||$code<200||$code>=300){ whatsappLogMessage($digits,$name,'outbound','template',json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),'failed','',$mid,(string)$resp); return [false,'Meta WhatsApp template failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'').(trim((string)$resp)?' — '.substr(strip_tags((string)$resp),0,420):'')]; }
        $j=json_decode((string)$resp,true); $metaId=(string)($j['messages'][0]['id']??''); whatsappLogMessage($digits,$name,'outbound','template','Template: '.$templateName,'sent',$metaId,$mid,(string)$resp); return [true,'WhatsApp template sent'];
    }
    // Generic provider fallback: send the same parameters as a normal JSON message.
    $api=trim((string)getSetting('whatsapp_api_url')); $key=trim((string)getSetting('whatsapp_api_key')); if($api==='') return [false,'WhatsApp provider API URL is not configured.']; if(!function_exists('curl_init')) return [false,'PHP cURL extension is required.'];
    $payload=['to'=>$digits,'phone'=>$digits,'template'=>$templateName,'language'=>$language,'parameters'=>array_values($parameters),'message'=>implode(' | ',array_map('strval',$parameters))]; $headers=['Content-Type: application/json']; if($key!=='')$headers[]='Authorization: Bearer '.$key;
    $ch=curl_init($api); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_TIMEOUT=>30]); $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($ce||$code<200||$code>=300) return [false,'WhatsApp provider failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'')];
    whatsappLogMessage($digits,$name,'outbound','template','Template: '.$templateName,'sent','',$mid,(string)$resp); return [true,'WhatsApp template sent'];
}

function whatsappSendTextToMember(array $m,string $message,int $timeout=30,int $connectTimeout=10): array {
    $timeout=max(1,min(30,$timeout)); $connectTimeout=max(1,min(10,$connectTimeout));
    $mobile=(string)($m['mobile']??''); $name=(string)($m['name']??'Member'); $mid=(int)($m['id']??0);
    $digits=memberContactDigits($mobile);
    if($digits==='') return [false,'Member mobile number is missing.'];
    if(getSetting('whatsapp_enabled','1')!=='1') return [false,'WhatsApp sending is disabled.'];
    $mode=strtolower(trim((string)getSetting('whatsapp_provider_mode','Meta Cloud API')));
    if(strpos($mode,'meta')!==false || strpos($mode,'business')!==false){
        $token=trim((string)getSetting('whatsapp_api_key')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id'));
        $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
        if($token===''||$phoneId==='') return [false,'Meta Access Token और Phone Number ID configure करें।'];
        if(!function_exists('curl_init')) return [false,'PHP cURL extension आवश्यक है।'];
        $url='https://graph.facebook.com/'.rawurlencode($gv).'/'.$phoneId.'/messages';
        $payload=['messaging_product'=>'whatsapp','to'=>$digits,'type'=>'text','text'=>['preview_url'=>false,'body'=>$message]];
        $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_CONNECTTIMEOUT=>$connectTimeout,CURLOPT_TIMEOUT=>$timeout]);
        $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        if($ce||$code<200||$code>=300){ whatsappLogMessage($digits,$name,'outbound','text',$message,'failed','',$mid,(string)$resp); return [false,'Meta WhatsApp failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'').(trim((string)$resp)?' — '.substr(strip_tags((string)$resp),0,300):'')]; }
        $j=json_decode((string)$resp,true); $metaId=(string)($j['messages'][0]['id']??''); whatsappLogMessage($digits,$name,'outbound','text',$message,'sent',$metaId,$mid,(string)$resp); return [true,'Message sent'];
    }
    $api=trim((string)getSetting('whatsapp_api_url')); $key=trim((string)getSetting('whatsapp_api_key'));
    if($api==='') return [false,'WhatsApp provider API URL is not configured.'];
    if(!function_exists('curl_init')) return [false,'PHP cURL extension is required.'];
    $payload=['to'=>$digits,'phone'=>$digits,'message'=>$message]; $headers=['Content-Type: application/json']; if($key!=='')$headers[]='Authorization: Bearer '.$key;
    $ch=curl_init($api); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_CONNECTTIMEOUT=>$connectTimeout,CURLOPT_TIMEOUT=>$timeout]); $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($ce||$code<200||$code>=300){ whatsappLogMessage($digits,$name,'outbound','text',$message,'failed','',$mid,(string)$resp); return [false,'WhatsApp provider failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'')]; }
    whatsappLogMessage($digits,$name,'outbound','text',$message,'sent','',$mid,(string)$resp); return [true,'Message sent'];
}

function whatsappSendImageToMember(array $m, array $file, string $caption=''): array {
    $mobile=(string)($m['mobile']??''); $name=(string)($m['name']??'Member'); $mid=(int)($m['id']??0);
    $digits=memberContactDigits($mobile);
    if($digits==='') return [false,'Member mobile number is missing.'];
    if(getSetting('whatsapp_enabled','1')!=='1') return [false,'WhatsApp sending is disabled.'];
    $mode=strtolower(trim((string)getSetting('whatsapp_provider_mode','Meta Cloud API')));
    if(strpos($mode,'meta')===false && strpos($mode,'business')===false) return [false,'Image attachment sending requires Meta Cloud API mode.'];
    $token=trim((string)getSetting('whatsapp_api_key')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id'));
    $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
    if($token===''||$phoneId==='') return [false,'Meta Access Token और Phone Number ID configure करें।'];
    if(!function_exists('curl_init')) return [false,'PHP cURL extension आवश्यक है।'];
    $tmp=(string)($file['tmp_name']??''); $mime=(new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    $allowed=['image/jpeg','image/png'];
    if(!in_array($mime,$allowed,true)) return [false,'केवल JPG या PNG image भेज सकते हैं।'];
    if((int)($file['size']??0)>5*1024*1024) return [false,'Image 5 MB से छोटी होनी चाहिए।'];
    $uploadUrl='https://graph.facebook.com/'.$gv.'/'.$phoneId.'/media';
    $ch=curl_init($uploadUrl);
    curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token],CURLOPT_POSTFIELDS=>['messaging_product'=>'whatsapp','file'=>new CURLFile($tmp,$mime,(string)($file['name']??'image'))],CURLOPT_TIMEOUT=>45]);
    $uploadResp=curl_exec($ch); $uploadCode=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $uploadErr=curl_error($ch); curl_close($ch);
    $uploadJson=json_decode((string)$uploadResp,true); $mediaId=(string)($uploadJson['id']??'');
    if($uploadErr||$uploadCode<200||$uploadCode>=300||$mediaId==='') return [false,'Meta image upload failed'.($uploadCode?' (HTTP '.$uploadCode.')':'').($uploadErr?': '.$uploadErr:'')];
    $payload=['messaging_product'=>'whatsapp','to'=>$digits,'type'=>'image','image'=>['id'=>$mediaId]];
    if(trim($caption)!=='') $payload['image']['caption']=function_exists('mb_substr')?mb_substr(trim($caption),0,1024):substr(trim($caption),0,1024);
    $url='https://graph.facebook.com/'.$gv.'/'.$phoneId.'/messages';
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),CURLOPT_TIMEOUT=>45]);
    $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($ce||$code<200||$code>=300){ whatsappLogMessage($digits,$name,'outbound','image',$caption,'failed',$mediaId,$mid,(string)$resp); return [false,'Meta image send failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'')]; }
    $j=json_decode((string)$resp,true); whatsappLogMessage($digits,$name,'outbound','image',$caption,'sent',(string)($j['messages'][0]['id']??$mediaId),$mid,(string)$resp);
    return [true,'Image sent'];
}

function pdfClean(string $s): string {
    $s = strip_tags($s);
    $s = iconv('UTF-8','Windows-1252//TRANSLIT//IGNORE',$s);
    $s = str_replace(["\\","(",")"],["\\\\","\\(","\\)"],$s);
    return $s;
}
function excelCell(mixed $v): string {
    $s=(string)$v;
    return '<Cell><Data ss:Type="String">'.h($s).'</Data></Cell>';
}
function excelRow(array $cells): string {
    $style=(string)($cells['__style']??'');$allowed=['Title','Subtitle','Section','Header','Total'];
    if(isset($cells['__cells'])&&is_array($cells['__cells']))$cells=$cells['__cells'];
    else unset($cells['__style']);
    $x='<Row'.(in_array($style,$allowed,true)?' ss:StyleID="'.$style.'"':'').'>'; foreach($cells as $i=>$c){ if($i===0&&in_array($style,['Title','Subtitle','Section'],true))$x.='<Cell ss:MergeAcross="9"><Data ss:Type="String">'.h((string)$c).'</Data></Cell>';else $x.=excelCell($c); } return $x.'</Row>';
}
function sendExcelWorkbook(string $filename, array $sheets): never {
    $xml='<?xml version="1.0" encoding="UTF-8"?>'.PHP_EOL
        .'<?mso-application progid="Excel.Sheet"?>'.PHP_EOL
        .'<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">'
        .'<Styles>
<Style ss:ID="Default" ss:Name="Normal"><Alignment ss:Vertical="Center" ss:WrapText="1"/><Font ss:FontName="Calibri" ss:Size="10" ss:Color="#1A2B3C"/><Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#E8EEF5"/></Borders></Style>
<Style ss:ID="Title"><Alignment ss:Horizontal="Center" ss:Vertical="Center"/><Font ss:FontName="Calibri" ss:Size="20" ss:Bold="1" ss:Color="#FFFFFF"/><Interior ss:Color="#0A3D7A" ss:Pattern="Solid"/></Style>
<Style ss:ID="Subtitle"><Alignment ss:Horizontal="Center" ss:Vertical="Center"/><Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1" ss:Color="#0A3D7A"/><Interior ss:Color="#E8F1FC" ss:Pattern="Solid"/></Style>
<Style ss:ID="Section"><Alignment ss:Vertical="Center"/><Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1" ss:Color="#FFFFFF"/><Interior ss:Color="#1265D8" ss:Pattern="Solid"/></Style>
<Style ss:ID="Header"><Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/><Font ss:FontName="Calibri" ss:Size="10" ss:Bold="1" ss:Color="#0A3D7A"/><Interior ss:Color="#D6E8FA" ss:Pattern="Solid"/><Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2" ss:Color="#1265D8"/></Borders></Style>
<Style ss:ID="Total"><Font ss:FontName="Calibri" ss:Size="10" ss:Bold="1" ss:Color="#0D6B3A"/><Interior ss:Color="#E6F7EF" ss:Pattern="Solid"/></Style>
<Style ss:ID="Money"><Alignment ss:Horizontal="Right"/><Font ss:FontName="Calibri" ss:Size="10" ss:Color="#1A2B3C"/><NumberFormat ss:Format="#,##0.00"/></Style>
<Style ss:ID="Good"><Font ss:FontName="Calibri" ss:Size="10" ss:Color="#0D6B3A"/><Interior ss:Color="#E6F7EF" ss:Pattern="Solid"/></Style>
<Style ss:ID="Warn"><Font ss:FontName="Calibri" ss:Size="10" ss:Color="#B45309"/><Interior ss:Color="#FFF7ED" ss:Pattern="Solid"/></Style>
</Styles>';
    foreach($sheets as $name=>$data){
        $xml.='<Worksheet ss:Name="'.h(substr((string)$name,0,31)).'"><Table>';
        foreach(($data['widths']??[]) as $width){$xml.='<Column ss:AutoFitWidth="0" ss:Width="'.max(28,min(420,(int)$width)).'"/>';}
        if(isset($data['headers'])){
            $xml.='<Row ss:StyleID="Header">'; foreach($data['headers'] as $c) $xml.=excelCell($c); $xml.='</Row>';
        }
        foreach(($data['rows']??[]) as $row) $xml.=excelRow($row);
        $xml.='</Table></Worksheet>';
    }
    $xml.='</Workbook>';
    header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
    header('Content-Disposition: attachment; filename="'.preg_replace('/[^A-Za-z0-9_.-]/','_',$filename).'"');
    header('Pragma: no-cache'); echo $xml; exit;
}
function sendSimplePdf(string $filename, string $title, array $lines): never {
    $wrapped=[];
    foreach($lines as $line){
        $line=(string)$line;
        $parts=preg_split('/\\r?\\n/',$line);
        foreach($parts as $part){
            $part=trim($part);
            if($part===''){ $wrapped[]=''; continue; }
            while(strlen($part)>92){ $wrapped[]=substr($part,0,92); $part=substr($part,92); }
            $wrapped[]=$part;
        }
    }
    $content="BT\n/F1 16 Tf\n50 800 Td\n(".pdfClean($title).") Tj\n/F1 10 Tf\n0 -24 Td\n";
    $lineNo=0;
    foreach($wrapped as $line){
        if($lineNo>0) $content.="0 -15 Td\n";
        $content.="(".pdfClean($line).") Tj\n";
        $lineNo++;
        if($lineNo>=48) break;
    }
    $content.="ET\n";
    $objects=[];
    $objects[]="<< /Type /Catalog /Pages 2 0 R >>";
    $objects[]="<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    $objects[]="<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>";
    $objects[]="<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
    $objects[]="<< /Length ".strlen($content)." >>\nstream\n".$content."endstream";
    $pdf="%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"; $offsets=[0];
    foreach($objects as $i=>$obj){ $offsets[$i+1]=strlen($pdf); $pdf.=($i+1)." 0 obj\n".$obj."\nendobj\n"; }
    $xref=strlen($pdf); $pdf.="xref\n0 ".(count($objects)+1)."\n0000000000 65535 f \n";
    for($i=1;$i<=count($objects);$i++) $pdf.=sprintf('%010d 00000 n ',$offsets[$i])."\n";
    $pdf.="trailer\n<< /Size ".(count($objects)+1)." /Root 1 0 R >>\nstartxref\n".$xref."\n%%EOF";
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="'.preg_replace('/[^A-Za-z0-9_.-]/','_',$filename).'"');
    header('Content-Length: '.strlen($pdf));
    echo $pdf; exit;
}

function sendFinancialReportPdf(string $filename, string $organization, array $metrics, array $loans, array $paymentSummary, array $members): never {
    $pages=[]; $content=''; $y=0.0;
    $color=function(string $hex): array { $hex=ltrim($hex,'#'); return [hexdec(substr($hex,0,2))/255,hexdec(substr($hex,2,2))/255,hexdec(substr($hex,4,2))/255]; };
    $rect=function(float $x,float $y,float $w,float $h,string $fill,?string $stroke=null) use (&$content,$color): void { [$r,$g,$b]=$color($fill); $content.=sprintf("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n",$r,$g,$b,$x,$y,$w,$h); if($stroke!==null){[$r,$g,$b]=$color($stroke);$content.=sprintf("%.3f %.3f %.3f RG 0.5 w %.2f %.2f %.2f %.2f re S\n",$r,$g,$b,$x,$y,$w,$h);} };
    $txt=function(float $x,float $y,float $size,string $text,string $hex='17324D',int $max=140) use (&$content,$color): void { $v=@iconv('UTF-8','Windows-1252//TRANSLIT//IGNORE',$text); if($v===false)$v=$text; $v=substr($v,0,$max); $v=str_replace(["\\","(",")"],["\\\\","\\(","\\)"],$v); [$r,$g,$b]=$color($hex); $content.=sprintf("BT /F1 %.1f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n",$size,$r,$g,$b,$x,$y,$v); };
    $newPage=function(string $continued='') use (&$pages,&$content,&$y,$rect,$txt,$organization): void { if($content!=='')$pages[]=$content; $content=''; $rect(0,0,842,595,'FFFFFF');$rect(24,535,794,40,'102A43');$rect(24,535,8,40,'16A36A');$txt(42,558,15,'GS SURAHA SAHYOG SAMITI','FFFFFF',70);$txt(42,544,8.5,'FINANCIAL REPORT'.($continued!==''?'  |  '.$continued:''),'CBE4F7',85);$txt(584,558,7,'Generated: '.date('d-m-Y h:i A'),'FFFFFF',48);$txt(584,544,7,'Organization: '.$organization,'D8EAF5',48);$y=510; };
    $section=function(string $label) use (&$y,$rect,$txt): void { $rect(30,$y-4,782,20,'0B5DB7');$txt(40,$y+2,10.5,strtoupper($label),'FFFFFF',100);$y-=29; };
    $newPage('');
    $rect(30,496,782,28,'EAF3FF','C9DDF5');$txt(42,506,14,'GS Suraha Finance - Report','123B68',70);$txt(650,507,8,'Period: All Records','536A83',40);$y=483;
    $cardColors=['E8F3FF','E8F8EE','FFF4E0','F0ECFF','E7F8F8'];
    for($i=0;$i<count($metrics);$i++){
        $row=(int)floor($i/5);$col=$i%5;$x=30+$col*157;$cy=432-$row*54;
        $rect($x,$cy,150,46,$cardColors[$col],'C9D6E5');$txt($x+8,$cy+29,7.1,(string)$metrics[$i][0],'4A5F77',29);$txt($x+8,$cy+11,10,(string)$metrics[$i][1],'17324D',25);
    }
    $y=365;
    $section('Loan Summary');
    if(!$loans){$rect(30,$y-1,782,20,'F0F6FC','DCE7F2');$txt(38,$y+5,8,'No loan records found. Loan summary is empty because no loans exist in the database.','536A83',120);$y-=29;}
    else {
        $rect(30,$y-4,782,17,'DCEBFA');$txt(36,$y+1,7.1,'Loan ID','17324D',14);$txt(88,$y+1,7.1,'Member ID / Name','17324D',29);$txt(285,$y+1,7.1,'Principal','17324D',18);$txt(385,$y+1,7.1,'EMI Total','17324D',18);$txt(485,$y+1,7.1,'EMI Paid','17324D',18);$txt(585,$y+1,7.1,'Outstanding','17324D',20);$txt(700,$y+1,7.1,'Paid / Pending','17324D',24);$y-=19;
        foreach($loans as $i=>$l){ if($y<82){$newPage('Loan Summary continued');$section('Loan Summary - Continued');$rect(30,$y-4,782,17,'DCEBFA');$txt(36,$y+1,7.1,'Loan ID','17324D');$txt(88,$y+1,7.1,'Member ID / Name','17324D');$txt(285,$y+1,7.1,'Principal','17324D');$txt(385,$y+1,7.1,'EMI Total','17324D');$txt(485,$y+1,7.1,'EMI Paid','17324D');$txt(585,$y+1,7.1,'Outstanding','17324D');$txt(700,$y+1,7.1,'Paid / Pending','17324D');$y-=19;}
            if($i%2===0)$rect(30,$y-5,782,16,'F5F9FD');$txt(36,$y,7.1,'#'.($l['id']??''),'334B66',12);$txt(88,$y,7.1,(string)($l['code']??'').' '.(string)($l['name']??''),'334B66',38);$txt(285,$y,7.1,'Rs. '.number_format((float)$l['principal'],2),'334B66',22);$txt(385,$y,7.1,'Rs. '.number_format((float)$l['total_emi'],2),'334B66',22);$txt(485,$y,7.1,'Rs. '.number_format((float)$l['paid_emi'],2),'334B66',22);$txt(585,$y,7.1,'Rs. '.number_format(max(0,(float)$l['total_emi']-(float)$l['paid_emi']),2),'334B66',24);$txt(700,$y,7.1,(int)$l['paid_count'].' / '.(int)$l['pending_count'],'334B66',15);$y-=16;
        }
    }
    $y-=22;
    if($y<120){$newPage('Payment and Member Summary');}
    $section('Payment Summary');
    foreach($paymentSummary as $label=>$value){$rect(30,$y-4,782,17,'F1F6FC','DCE7F2');$txt(40,$y+1,8,$label.': '.(string)$value,'334B66',100);$y-=20;}
    $y-=3;$section('Member Summary');
    $heads=[['S.No',30],['Member ID',58],['Name',108],['Mobile No.',220],['Savings',305],['Loan',385],['Interest',470],['EMI Due',550],['Paid',640],['Status',730]];
    $drawHead=function() use (&$y,$rect,$txt,$heads): void {$rect(30,$y-5,782,18,'0B5DB7');foreach($heads as [$h,$x])$txt((float)$x,$y,6.8,$h,'FFFFFF',18);$y-=19;};$drawHead();
    foreach($members as $i=>$m){if($y<48){$newPage('Member Summary continued');$section('Member Summary - Continued');$drawHead();}if($i%2===0)$rect(30,$y-5,782,17,'F1F6FB');$values=[[(string)($i+1),30],[(string)$m['code'],58],[(string)$m['name'],108],[(string)$m['mobile'],220],['Rs. '.number_format((float)$m['contribution_total'],2),305],['Rs. '.number_format((float)$m['loan_principal'],2),385],['Rs. '.number_format((float)$m['interest_earned'],2),470],['Rs. '.number_format((float)$m['emi_outstanding'],2),550],['Rs. '.number_format((float)$m['emi_paid'],2),640],[(string)$m['status'],730]];foreach($values as [$v,$x])$txt((float)$x,$y,6.6,(string)$v,'334B66',22);$y-=17;}
    if($content!=='')$pages[]=$content;
    $pageCount=count($pages);foreach($pages as $i=>&$pg){$pg.="0.5 w 0.75 0.75 0.75 RG 30 32 m 812 32 l S\n";$save=$content;$content=$pg;$txt(30,20,7,$organization.'  |  Financial Report','56708A',100);$txt(755,20,7,'Page '.($i+1).' of '.$pageCount,'56708A',20);$pg=$content;$content=$save;}unset($pg);
    $objects=[];$objects[1]='<< /Type /Catalog /Pages 2 0 R >>';$kids=[];for($i=0;$i<$pageCount;$i++)$kids[]=(5+$i*2).' 0 R';$objects[2]='<< /Type /Pages /Kids ['.implode(' ',$kids).'] /Count '.$pageCount.' >>';$objects[3]='<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
    foreach($pages as $i=>$stream){$pageId=5+$i*2;$streamId=$pageId+1;$objects[$pageId]='<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 3 0 R >> >> /Contents '.$streamId.' 0 R >>';$objects[$streamId]='<< /Length '.strlen($stream)." >>\nstream\n".$stream."endstream";}
    ksort($objects);$pdf="%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";$offsets=[0];foreach($objects as $id=>$obj){$offsets[$id]=strlen($pdf);$pdf.=$id." 0 obj\n".$obj."\nendobj\n";}$xref=strlen($pdf);$size=max(array_keys($objects))+1;$pdf.="xref\n0 ".$size."\n0000000000 65535 f \n";for($i=1;$i<$size;$i++)$pdf.=isset($offsets[$i])?sprintf('%010d 00000 n ',$offsets[$i])."\n":"0000000000 00000 f \n";$pdf.="trailer\n<< /Size ".$size." /Root 1 0 R >>\nstartxref\n".$xref."\n%%EOF";
    header('Content-Type: application/pdf');header('Content-Disposition: attachment; filename="'.preg_replace('/[^A-Za-z0-9_.-]/','_',$filename).'"');header('Content-Length: '.strlen($pdf));echo $pdf;exit;
}
function assetUrl(string $path): string {
    if (preg_match('~^(?:https?:)?//~i', $path)) return $path;
    $base = function_exists('siteBaseUrl') ? rtrim(siteBaseUrl(), '/') : '';
    return $base . '/' . ltrim($path, '/');
}
function brandingAssetSetting(string $key, string $fallback): string {
    $value=trim(getSetting($key,''));
    if($value==='') return $fallback;
    if(preg_match('~^(?:https?:)?//~i',$value)) return $value;
    $local=__DIR__.'/'.ltrim($value,'/');
    return is_file($local) ? $value : $fallback;
}
function deleteBrandingAsset(string $key, string $fallback): void {
    $old=trim(getSetting($key,''));
    if($old!=='' && !preg_match('~^(?:https?:)?//~i',$old) && str_starts_with($old,'uploads/branding/')){
        $oldPath=__DIR__.'/'.ltrim($old,'/'); if(is_file($oldPath)) @unlink($oldPath);
    }
    setSetting($key,$fallback);
}

function layout(string $title, string $content): void {
    global $db,$route;
    $u=user(); $topMember=($u && $u['role']==='member') ? memberOfUser() : null; $soc=getSetting('society_name','GS Suraha Sahyog Samiti'); $tag=getSetting('society_tagline','Finance Co-operative Society'); $logo=brandingAssetSetting('header_logo','assets/logo.png'); $logoUrl=assetUrl($logo); $favicon=brandingAssetSetting('site_favicon','');
    $dashboardHeaderArtwork=brandingAssetSetting('front_header_image','assets/front-header-test.png');
    $dashboardHeaderArtworkUrl=$dashboardHeaderArtwork!==''?assetUrl($dashboardHeaderArtwork):'';
    $dashboardHeaderArtworkFit=in_array(getSetting('front_header_image_fit','cover'),['contain','cover','auto'],true)?getSetting('front_header_image_fit','cover'):'cover';
    if($dashboardHeaderArtwork==='assets/front-header-test.png') $dashboardHeaderArtworkFit='cover';
    $cssUrl=assetUrl('assets/style.css?v=20261106-v215-desktop-ui-gpay');
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h($title)?> · <?=h($soc)?></title><link rel="stylesheet" href="<?=h($cssUrl)?>"><?php if($favicon!==''): ?><link rel="icon" href="<?=h(assetUrl($favicon))?>"><?php endif; ?><body class="<?= $u ? ('authenticated-page role-'.h((string)$u['role'])) : (($route==='login') ? 'login-page' : 'public-page') ?><?= ($u && $title==='Dashboard') ? ' dashboard-layout' : '' ?><?= ($route==='member-dashboard') ? ' member-dashboard-screen' : '' ?>">
<?php if(!$u): ?>
<?= $content ?>
</body></html>
<?php return; endif; ?>
<div class="app">
<aside class="sidebar" id="appSidebar" aria-label="Main navigation">
  <div class="sidebar-head"><div class="brand"><img src="<?=h($logoUrl)?>"><div><b><?=h($soc)?></b><small><?=h($tag)?></small></div></div><button class="sidebar-close" type="button" onclick="closeMobileMenu()" aria-label="Close menu">×</button></div>
  <?php $sideMember=null; $sideAvailable=0.0; $sideSocietyDeposits=0.0; $sideSocietyLoans=0.0; if(($u['role']??'')==='member'): try { $sideMember=memberOfUser(); if($sideMember){ $sideMid=(int)$sideMember['id']; $sideDeposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id={$sideMid} AND status='Paid'"); $sideAll=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'"); $sideInterest=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger WHERE member_id={$sideMid}"); $sideRefund=0.0; try { $sideRefund=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE member_id={$sideMid} AND status='Approved'"); } catch (Throwable $ignored) { $sideRefund=0.0; } $sideAvailable=($sideMember['status']??'')==='Closed'?0:max(0,round($sideDeposit+$sideInterest-$sideRefund,2)); $sideSocietyDeposits=$sideAll; try { $sideSocietyLoans=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans"); } catch (Throwable $ignored) { $sideSocietyLoans=0.0; } } } catch (Throwable $ignored) { $sideMember=null; } endif; if(($u['role']??'')==='member'): ?>
  <?php endif; ?>
  <?php if($u && in_array($u['role'],['admin','staff'],true)): ?>
  <nav>
   <?php if($u['role']==='admin' && isSuperAdmin($u)): ?><a href="?route=admin-panel"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg></i><span>Admin Panel</span></a><?php endif; ?>
   <?php if(showNav('dashboard')): ?><a href="?route=dashboard"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10.5V20h13v-9.5"/><path d="M9.5 20v-5h5v5"/></svg></i><span>Dashboard</span></a><?php endif; ?>
   <?php if(showNav('members')): ?><a href="?route=members"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3"/><path d="M3.5 19c.7-3.2 2.5-5 5.5-5s4.8 1.8 5.5 5"/><circle cx="17" cy="9" r="2.3"/><path d="M15.5 14.5c2.6.1 4.2 1.6 4.9 4.5"/></svg></i><span>Members</span></a><?php endif; ?>
   <?php if(showNav('contributions')): ?><a href="?route=contributions"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18M7 14h4"/><circle cx="17" cy="14" r="1.5"/></svg></i><span>Contributions</span></a><?php endif; ?>
   <?php if(showNav('loans')): ?><a href="?route=loan-applications"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3.5h9l3 3V20.5H6z"/><path d="M15 3.5v4h4M9 12h6M9 16h5"/></svg></i><span>Loan Applications</span></a><?php endif; ?>
   <?php if(showNav('loans')): ?><a href="?route=loans"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16v12H4z"/><path d="M7 7V5h10v2M8 12h8"/><circle cx="12" cy="15" r="2"/></svg></i><span>Loans & EMI</span></a><?php endif; ?>
   <?php if(showNav('payments')): ?><a href="?route=emi-payments"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 3v18M11 6.5C9.8 5.6 7.8 5.5 6.7 6.6c-1.5 1.6.2 3.1 2.3 3.8 2.5.8 4.3 1.8 3.7 4-.5 2-3.5 2.5-5.7 1.2"/></svg></i><span>EMI Payments</span></a><?php endif; ?>
   <?php if(showNav('reminders')): ?><a href="?route=contribution-reminders"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3v18M7 7h7.5a3 3 0 0 1 0 6H8a3 3 0 0 0 0 6h9"/></svg></i><span>Contribution Reminders</span></a><?php endif; ?>
   <?php if(showNav('reminders')): ?><a href="?route=emi-reminders"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg></i><span>EMI Reminders</span></a><?php endif; ?>
   <?php if(showNav('reports')): ?><a href="?route=reports"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V5M4 19h17"/><rect x="7" y="12" width="3" height="5" rx=".5"/><rect x="12" y="9" width="3" height="8" rx=".5"/><rect x="17" y="6" width="3" height="11" rx=".5"/></svg></i><span>Reports</span></a><?php endif; ?>
   <?php if($u['role']==='admin'): ?><?php if(showNav('settings')): ?><a href="?route=control-center"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.4 1a8 8 0 0 0-2.1-1.2L14 3h-4l-.4 2.7a8 8 0 0 0-2.1 1.2l-2.4-1-2 3.4 2 1.5A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.4-1a8 8 0 0 0 2.1 1.2L10 21h4l.4-2.7a8 8 0 0 0 2.1-1.2l2.4 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z"/></svg></i><span>Settings</span></a><?php endif; ?><?php if(showNav('admins')): ?><a href="?route=admin-users"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="7" r="3"/><path d="M5 20c.8-4 3-6 7-6s6.2 2 7 6"/><path d="M18 5v4M16 7h4"/></svg></i><span>Admin IDs</span></a><?php endif; ?><?php if(showNav('users')): ?><a href="?route=staff-member-users"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="2.7"/><circle cx="16.5" cy="9" r="2.2"/><path d="M3.5 19c.7-3.2 2.5-5 5.5-5s4.8 1.8 5.5 5M14.5 14.5c2.7.2 4.4 1.8 5 4.5"/></svg></i><span>Staff & Member IDs</span></a><?php if(showNav('users')): ?><a href="?route=staff-member-assignment"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="8" r="3"/><circle cx="17" cy="8" r="3"/><path d="M2 20c.5-4 2.5-6 6-6s5.5 2 6 6M14 15c4-1 6 1 7 5"/></svg></i><span>Staff–Member Mapping</span></a><a href="?route=member-balances"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M7 15h4"/></svg></i><span>Member Available Balance</span></a><?php endif; ?><?php endif; ?><?php if(showAdminNav('whatsapp-center')): ?><a class="<?=($route==='whatsapp-center' && (($_GET['tab']??'home')==='home'))?'active':''?>" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M20 11.5a8 8 0 0 1-8 8H7l-4 2 1.5-4A8 8 0 1 1 20 11.5z"/><path d="M8 10h8M8 13h5"/></svg></i><span>Overview &amp; Chat</span></a><a href="?route=whatsapp-center&amp;tab=bulk"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 5h16v14H4zM7 9h10M7 13h7"/></svg></i><span>WhatsApp Center</span></a><?php endif; ?><?php if(showAdminNav('whatsapp-sms-center')): ?><a href="?route=whatsapp-sms-center"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 12h8M8 15h5"/></svg></i><span>WhatsApp Settings</span></a><?php endif; ?><?php if(showNav('funds')): ?><a href="?route=fund-adjustments"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 7h10"/><path d="m12 4 3 3-3 3"/><path d="M19 17H9"/><path d="m12 14-3 3 3 3"/></svg></i><span>Expenses & Withdrawals</span></a><?php endif; ?><?php if(showNav('backup')): ?><a href="?route=backup"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v11"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M5 20h14"/></svg></i><span>Backup</span></a><?php endif; ?><?php endif; ?>
  </nav>
  <?php elseif($u): ?>
  <nav>
   <a href="?route=member-dashboard"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10.5V20h13v-9.5"/><path d="M9.5 20v-5h5v5"/></svg></i><span>My Dashboard</span></a>
   <a href="?route=member-loan-apply"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4h12v16H6z"/><path d="M9 8h6M9 12h6M12 15v4M10 17h4"/></svg></i><span>Apply Loan</span></a>
   <a href="?route=member-pay"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9h18M7 14h4"/></svg></i><span>Pay Contribution</span></a>
   <a href="?route=member-emi-pay"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 11h2M12 11h2M16 11h0M8 15h2M12 15h2M16 15h0"/></svg></i><span>Pay EMI</span></a>
   <a href="?route=account-settings"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3"/><path d="M5 20c.8-4 3-6 7-6s6.2 2 7 6"/></svg></i><span>My Account</span></a><a href="?route=member-profile"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3"/><path d="M6 20c.7-3.6 2.7-5.5 6-5.5s5.3 1.9 6 5.5"/><path d="M17 4v3M15.5 5.5h3"/></svg></i><span>My Profile</span></a>
   <a class="member-close-nav" href="?route=member-close-request"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M6 7h12M9 7V4h6v3M8 10v7M12 10v7M16 10v7"/><path d="M5 7l1 14h12l1-14"/></svg></i><span>Close ID / Refund</span></a>
   <a href="?route=member-payment-history"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 7v5l3 2"/></svg></i><span>Payment History</span></a>
   <a href="?route=notifications"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg></i><span>Notifications / सूचनाएँ</span></a>
  <a class="<?=($route==='member-financial-summary'?'active':'')?>" href="?route=member-financial-summary"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h4"/></svg></i><span>My Financial Summary</span></a>
  </nav>
  <?php endif; ?>
  <div class="side-bottom"><div class="online">● System Online</div><?php if($u): ?><a class="side-logout" href="?route=logout"><i class="sidebar-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M10 5H5v14h5"/><path d="M13 8l4 4-4 4M17 12H9"/></svg></i><span>Logout</span></a><?php endif; ?></div>
</aside>
<main class="main">
<header class="topbar topbar-with-artwork">
  <?php if($dashboardHeaderArtworkUrl!==''): ?><img class="topbar-artwork" src="<?=h($dashboardHeaderArtworkUrl)?>" alt="" aria-hidden="true" style="object-fit:<?=h($dashboardHeaderArtworkFit)?>" onerror="this.style.display='none'"><?php endif; ?>
  <button class="menu-toggle" type="button" aria-label="Open menu" onclick="toggleMobileMenu()">☰</button>
  <div class="topbar-brand"><img src="<?=h($logoUrl)?>" alt="GS Suraha"><div><b><?=h($soc)?></b><small><?=h($tag)?></small></div></div>
  <div class="mobile-brand"><img src="<?=h($logoUrl)?>" alt="GS"><div><b><?=h($soc)?></b><small><?=h($tag)?></small></div></div>
  <div class="top-actions">
    <a class="icon-btn notification-btn" href="?route=notifications" title="Notifications" aria-label="Notifications">🔔<?php $ncount=notificationCount(); ?><i><?=h((string)$ncount)?></i></a>
    <div class="top-user"><?php if($u): ?>
    <button class="avatar avatar-link profile-trigger" type="button" onclick="toggleProfileMenu(event)" aria-label="Open profile menu" aria-controls="profileMenu" aria-expanded="false">
      <?php if($topMember && !empty($topMember['photo'])): ?><img src="<?=memberFileUrl($topMember['photo'])?>" alt="<?=h($topMember['name'])?>"><?php else: ?><?=h(strtoupper(substr($u['username'],0,1)))?><?php endif; ?>
    </button>
    <span class="user-meta"><b><?=h(($u['display_name'] ?? '') ?: $u['username'])?></b><small><?=h($u['username'])?> · <?=h(ucfirst($u['role']))?></small></span>
    <div class="profile-menu" id="profileMenu">
      <div class="profile-menu-head">
        <div class="profile-menu-avatar"><?php if($topMember && !empty($topMember['photo'])): ?><img src="<?=memberFileUrl($topMember['photo'])?>" alt=""><?php else: ?><?=h(strtoupper(substr($u['username'],0,1)))?><?php endif; ?></div>
        <div><b><?=h($topMember['name'] ?? (($u['display_name'] ?? '') ?: $u['username']))?></b><small><?=h($u['username'])?> · <?=h(ucfirst($u['role']))?></small></div>
      </div>
      <div class="profile-menu-time">🕒 Login time: <b><?=h($_SESSION['login_time'] ?? 'Current session')?></b></div>
      <?php if($u['role']==='member'): ?><a href="?route=member-profile">👤 My Profile</a><?php endif; ?>
      <a href="?route=notifications">🔔 Notifications</a><a href="?route=account-settings">⚙ My Account</a><?php if($u['role']==='member'): ?><a href="?route=member-profile">📄 My Profile</a><?php endif; ?><a class="profile-logout" href="?route=logout">⇥ Logout</a>
    </div>
  <?php endif; ?></div>
  </div>
</header>
<?php if(false && getSetting('notice_enabled','1')==='1' && in_array($route,['dashboard'],true)):  // v209: upper notice hidden $noticeFeed=noticeFeed(); $noticeFeed=array_values(array_filter($noticeFeed,static fn($ni)=>!empty($ni['notice_type']) && $ni['notice_type']==='managed')); $staticNotice=trim(getSetting('notice_text')); if($staticNotice!=='') array_unshift($noticeFeed,['text'=>'📢 '.$staticNotice,'href'=>'#','created_at'=>date('Y-m-d H:i:s'),'notice_type'=>'static','notice_id'=>0]); if(!$noticeFeed) $noticeFeed=[['text'=>'📢 GS सुराहा सहयोग समिति की नवीनतम सूचना यहाँ प्रदर्शित होगी।','href'=>'#','created_at'=>date('Y-m-d H:i:s'),'notice_type'=>'empty','notice_id'=>0]]; $currentNoticeId=0; foreach($noticeFeed as $ni){ if(!empty($ni['notice_id'])){$currentNoticeId=(int)$ni['notice_id']; break;} } ?>
<div class="notice-bar notice-ticker <?=getSetting('notice_move','1')==='1'?'notice-moving':'notice-static'?>" style="--notice-duration:<?=h((string)max(5,min(180,(int)getSetting('notice_speed','35'))))?>s" aria-label="सूचना">
  <span class="notice-icon">📢</span>
  <div class="notice-label"><b>Notice</b><span class="hi-inline">सूचना</span></div>
  <div class="notice-viewport"><div class="notice-track" id="noticeTrack">
    <?php foreach($noticeFeed as $i=>$ni): ?><a class="notice-slide<?= $i===0?' active':'' ?>" href="<?=h($ni['href'])?>" data-index="<?=$i?>"><span><?=h($ni['text'])?></span></a><?php endforeach; ?>
  </div></div>
  <div class="notice-dots" id="noticeDots"><?php foreach($noticeFeed as $i=>$ni): ?><button type="button" class="notice-dot<?= $i===0?' active':'' ?>" data-index="<?=$i?>" aria-label="Notice <?=$i+1?>"></button><?php endforeach; ?></div>
  <?php if(in_array($u['role'],['admin','staff'],true) && $staticNotice!==''): ?><form method="post" action="?route=notice-action" class="notice-current-delete-form" onsubmit="return confirm('Current Notice delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="clear_static_notice"><button type="submit" class="notice-current-delete">🗑️ Delete</button></form><?php elseif(in_array($u['role'],['admin','staff'],true) && $currentNoticeId>0): ?><form method="post" action="?route=notice-action" class="notice-current-delete-form" onsubmit="return confirm('Current Notice delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_notice"><input type="hidden" name="id" value="<?=$currentNoticeId?>"><button type="submit" class="notice-current-delete">🗑️ Delete</button></form><?php endif; ?>
</div>
<script>
(function(){
  var ticker=document.querySelector('.notice-ticker');
  if(!ticker)return;
  var viewport=ticker.querySelector('.notice-viewport');
  var slides=Array.prototype.slice.call(ticker.querySelectorAll('.notice-slide'));
  var dots=Array.prototype.slice.call(ticker.querySelectorAll('.notice-dot'));
  if(!viewport||!slides.length)return;
  var index=0,raf=0,timer=0,startAt=0,duration=Math.max(5,Math.min(180,parseFloat(ticker.style.getPropertyValue('--notice-duration'))||35))*1000;
  var move=true;
  function stop(){if(raf)cancelAnimationFrame(raf);raf=0;if(timer)clearTimeout(timer);timer=0;}
  function place(slide,x){slide.style.setProperty('transform','translate3d('+x+'px,0,0)','important');}
  function show(next){
    stop();index=(next+slides.length)%slides.length;
    slides.forEach(function(slide,i){
      var active=i===index;
      if(slide.getAnimations)slide.getAnimations().forEach(function(a){a.cancel();});
      slide.classList.toggle('active',active);
      slide.style.setProperty('display',active?'flex':'none','important');slide.style.setProperty('position','absolute','important');
      slide.style.setProperty('left','0','important');slide.style.setProperty('top','0','important');
      slide.style.setProperty('visibility',active?'visible':'hidden','important');slide.style.setProperty('opacity',active?'1':'0','important');
      slide.style.setProperty('width','max-content','important');slide.style.setProperty('max-width','none','important');
      slide.style.setProperty('white-space','nowrap','important');slide.style.setProperty('transition','none','important');slide.style.setProperty('pointer-events',active?'auto':'none','important');
      var text=slide.querySelector('span');if(text){text.style.setProperty('display','block','important');text.style.setProperty('width','max-content','important');text.style.setProperty('max-width','none','important');text.style.setProperty('white-space','nowrap','important');text.style.setProperty('overflow','visible','important');}
    });
    dots.forEach(function(dot,i){dot.classList.toggle('active',i===index);});
    var slide=slides[index],vw=viewport.clientWidth||ticker.clientWidth||320;
    if(!move){place(slide,0);timer=setTimeout(function(){show(index+1);},6000);return;}
    var sw=Math.max(slide.scrollWidth,slide.getBoundingClientRect().width,80),from=vw+12,to=-sw-36;place(slide,from);startAt=0;
    function frame(now){if(!startAt)startAt=now;var progress=Math.min(1,(now-startAt)/duration);place(slide,from+(to-from)*progress);if(progress<1)raf=requestAnimationFrame(frame);else{raf=0;timer=setTimeout(function(){show(index+1);},250);}}
    raf=requestAnimationFrame(frame);
  }
  dots.forEach(function(dot){dot.addEventListener('click',function(){var n=parseInt(dot.getAttribute('data-index'),10);if(Number.isFinite(n))show(n);});});
  document.addEventListener('visibilitychange',function(){if(document.hidden)stop();else show(index);});
  window.addEventListener('resize',function(){show(index);});show(0);
})();
</script>
<?php endif; ?>
<div class="mobile-overlay" onclick="closeMobileMenu()"></div>
<section class="page"><?= $content ?></section>
<nav class="mobile-bottom-nav">
  <a class="<?=($route==='member-dashboard'||$route==='dashboard')?'active':''?>" href="?route=<?=($u && $u['role']==='member'?'member-dashboard':'dashboard')?>"><span>🏠</span><b>Home</b></a>
  <?php if($u && in_array($u['role'],['admin','staff'],true)): ?>
    <?php if($u['role']==='admin' && showAdminNav('whatsapp-center')): ?><a href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1"><span>💬</span><b>WhatsApp</b></a><?php endif; ?>
    <a href="?route=members"><span>👥</span><b>Members</b></a>
    <a href="?route=contributions"><span>₹</span><b>Money</b></a>
    <a href="?route=loans"><span>▤</span><b>Loans</b></a>
    <a href="?route=emi-payments"><span>₹</span><b>EMI</b></a>
  <?php else: ?>
    <a class="<?=($route==='member-profile')?'active':''?>" href="?route=member-profile"><span>👤</span><b>Member</b></a>
    <a class="<?=($route==='member-financial-summary')?'active':''?>" href="?route=member-financial-summary"><span>📊</span><b>Report</b></a>
    <a class="<?=($route==='notifications')?'active':''?>" href="?route=notifications"><span>📢</span><b>Notice</b></a>
  <?php endif; ?>
</nav>
<footer><div>GS Suraha Finance Co-operative Society · Secure · Transparent · Together</div><div class="footer-legal-links"><a href="terms-of-service.php">Terms of Use</a><a href="privacy-policy.php">Privacy Policy</a><a href="data-deletion.php">Data Deletion</a><a href="?route=refund-policy">Refund</a><a href="?route=disclaimer">Disclaimer</a><a href="?route=contact">Contact</a></div></footer>
</main></div>
<script>
function toggleLoginPassword(){const x=document.getElementById('loginPassword');const b=document.querySelector('.password-toggle');if(!x)return;const visible=x.type==='password';x.type=visible?'text':'password';if(b){b.textContent=visible?'Hide password':'Show password';b.setAttribute('aria-label',visible?'Hide password':'Show password');b.setAttribute('aria-pressed',visible?'true':'false');}}
function togglePasswordVisibility(button){const x=button&&button.parentElement?button.parentElement.querySelector('input'):null;if(!x)return;const visible=x.type==='password';x.type=visible?'text':'password';button.textContent=visible?'Hide':'Show';button.setAttribute('aria-pressed',visible?'true':'false');}


/* Open UPI in external app (PhonePe/GPay/Paytm) — required for Android WebView / Median / in-app browsers */
window.gsOpenUpiPayment = function(ev, plainUpi, intentUpi){
  if(ev){ ev.preventDefault(); }
  var ua=navigator.userAgent||'';
  var isAndroid=/Android/i.test(ua);
  var isIOS=/iPhone|iPad|iPod/i.test(ua);
  var isWebView=/(; wv\)|WebView|Median|Cordova|PhoneGap|Instagram|FBAN|FBAV)/i.test(ua)
    || (isAndroid && /Version\/[\d.]+/.test(ua) && !/Chrome\/[\d.]+ Mobile/.test(ua) && /wv/i.test(ua));
  var target=(isAndroid ? (intentUpi||plainUpi) : (plainUpi||intentUpi));
  if(!target)return false;
  // Use a separate browsing target so Android/embedded browsers can hand the intent
  // to the installed UPI app. Do not navigate back to plain upi:// after a delay:
  // that fallback was reopening the payment chooser inside the host app.
  try{
    if(isWebView && window.cordova && typeof window.open==='function') window.open(target,'_system');
    else window.open(target,'_blank','noopener');
  }catch(err){
    var a=document.createElement('a');a.href=target;a.target='_blank';a.rel='noopener noreferrer';
    document.body.appendChild(a);a.click();setTimeout(function(){a.remove();},1000);
  }
  return false;
};



function toggleMobileMenu(){
  var desktop=window.matchMedia('(min-width:901px)').matches;
  if(desktop){
    document.body.classList.toggle('sidebar-collapsed');
    try{localStorage.setItem('gs_sidebar_collapsed',document.body.classList.contains('sidebar-collapsed')?'1':'0');}catch(e){}
    return;
  }
  var willOpen=!document.body.classList.contains('sidebar-open');
  document.body.classList.toggle('sidebar-open',willOpen);
  document.body.classList.toggle('menu-active',willOpen);
  var menu=document.getElementById('appSidebar');
  if(menu) menu.setAttribute('aria-hidden',willOpen?'false':'true');
}
function closeMobileMenu(){
  var desktop=window.matchMedia('(min-width:901px)').matches;
  if(desktop){
    document.body.classList.add('sidebar-collapsed');
    try{localStorage.setItem('gs_sidebar_collapsed','1');}catch(e){}
  }
  document.body.classList.remove('sidebar-open','menu-active');
  var menu=document.getElementById('appSidebar');
  if(menu) menu.setAttribute('aria-hidden', desktop ? 'true' : 'true');
}
(function(){
  try{
    if(window.matchMedia('(min-width:901px)').matches && localStorage.getItem('gs_sidebar_collapsed')==='1'){
      document.body.classList.add('sidebar-collapsed');
    }
  }catch(e){}
  // Keep mobile/desktop classes in sync when the window is resized
  var mq=window.matchMedia('(min-width:901px)');
  function onBreakpoint(e){
    if(e.matches){
      document.body.classList.remove('sidebar-open','menu-active');
      var menu=document.getElementById('appSidebar');
      if(menu) menu.setAttribute('aria-hidden','false');
    } else {
      document.body.classList.remove('sidebar-collapsed');
      closeMobileMenu();
    }
  }
  if(mq.addEventListener) mq.addEventListener('change', onBreakpoint);
  else if(mq.addListener) mq.addListener(onBreakpoint);
})();
document.querySelectorAll('.sidebar a').forEach(function(a){
  a.addEventListener('click', function(){ closeMobileMenu(); });
});
function toggleProfileMenu(ev){
  if(ev) ev.stopPropagation();
  var menu=document.getElementById('profileMenu');
  var trigger=document.querySelector('.profile-trigger');
  if(!menu) return;
  var open=menu.classList.toggle('open');
  if(trigger) trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
}
document.addEventListener('click',function(e){
  var menu=document.getElementById('profileMenu');
  var trigger=document.querySelector('.profile-trigger');
  if(menu && menu.classList.contains('open') && !menu.contains(e.target) && !trigger.contains(e.target)){
    menu.classList.remove('open');
    if(trigger) trigger.setAttribute('aria-expanded','false');
  }
});
document.querySelectorAll('[data-confirm]').forEach(x=>x.addEventListener('click',e=>{if(!confirm(x.dataset.confirm))e.preventDefault()}));
/* Convert data tables into compact mobile cards so Member Summary, Calling Logs,
   Member Directory and other admin tables never push the page outside the screen. */
(function(){
  document.querySelectorAll('.table-wrap table:not(.doc-table)').forEach(function(table){
    table.classList.add('mobile-card-table');
    var heads=[];
    table.querySelectorAll('thead th').forEach(function(th){heads.push((th.textContent||'').trim());});
    table.querySelectorAll('tbody tr').forEach(function(row){
      Array.prototype.forEach.call(row.children,function(td,i){
        if(td.tagName!=='TD') return;
        if(td.hasAttribute('colspan')) return;
        td.setAttribute('data-label', heads[i] || 'Details');
      });
    });
  });
})();
(function(){var route=new URLSearchParams(location.search).get('route')||'';document.querySelectorAll('.mobile-bottom-nav a').forEach(function(a){var ar=new URLSearchParams(a.search).get('route')||'';if(ar===route)a.classList.add('active');});})();
</script></body></html>
<?php
}

initializeMemberInterestLedger();
$route=$_GET['route'] ?? (user() ? (user()['role']==='member'?'member-dashboard':'dashboard') : 'home');
$originalRoute=$route;
$loginPortal = in_array($route, ['member-login','admin-login','staff-login'], true) ? ($route==='member-login' ? 'member' : 'admin') : 'all';
if (in_array($route, ['member-login','admin-login','staff-login'], true)) $route='login';
if($route==='meta-connection'){ $_GET['comm_view']='meta'; $route='communications'; }
elseif($route==='sms-settings'){ $_GET['comm_view']='sms'; $route='communications'; }
elseif($route==='whatsapp-settings'){ $route='whatsapp-sms-center'; }
elseif($route==='whatsapp-embedded-signup') {
    requireRole(['admin']);
    $appId = '2161510128110351';
    $configId = '29735247966059908';
    ?><!doctype html><html lang="hi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WhatsApp Embedded Signup | GS Suraha</title><style>
     .id-card-page .id-card{border-radius:<?=$radius?>px}
     .id-card-page .id-card-head{background:linear-gradient(180deg,#ffffff,#f1f6fa)!important}
     .id-card-page .id-back-head{background:#138808!important}
     .id-card-page .id-back,.id-card-page .id-back-body{background:#f4fbf4!important}
     .id-card-page .id-card:before{background:none!important}
     .id-card-page .id-card-foot{background:#138808!important;border-top:0!important}
     .id-card-page .id-card-foot:after{display:none!important}
     .id-card-page .id-card,.id-card-page .id-row b{color:<?=h($textColor)?>}
     .id-card-page .id-back-body p{color:<?=h($backText)?>!important}
     .id-card-page .id-card-foot b{color:#ffffff!important}</style></head><body><main class="wrap"><h2>GS Suraha — WhatsApp Embedded Signup</h2><p>Meta के माध्यम से WhatsApp Business अकाउंट कनेक्ट करने के लिए नीचे बटन दबाएँ।</p><button id="waSignupBtn" type="button">Connect WhatsApp with Meta</button><p id="waStatus" role="status">Meta SDK लोड हो रहा है…</p><h3>Session Info</h3><pre id="waSession">Signup शुरू होने के बाद WABA ID और Phone Number ID यहाँ दिखेंगे।</pre><p class="note"><b>ध्यान दें:</b> यह पेज signup flow लॉन्च करता है और session info दिखाता है। Access token को browser में सेव नहीं किया जाता। Token exchange और सुरक्षित server-side storage के लिए Meta App Secret तथा backend configuration आवश्यक है।</p><p><a href="?route=whatsapp-sms-center">← WhatsApp Settings पर वापस जाएँ</a></p></main><script>
window.fbAsyncInit=function(){FB.init({appId:'2161510128110351',autoLogAppEvents:true,xfbml:true,version:'v26.0'});document.getElementById('waStatus').textContent='Meta SDK तैयार है।';};
(function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0];if(d.getElementById(id))return;js=d.createElement(s);js.id=id;js.src='https://connect.facebook.net/en_US/sdk.js';fjs.parentNode.insertBefore(js,fjs);})(document,'script','facebook-jssdk');
let waSessionInfo=null;
window.addEventListener('message',function(event){if(event.origin!=='https://www.facebook.com'&&event.origin!=='https://web.facebook.com')return;let data;try{data=typeof event.data==='string'?JSON.parse(event.data):event.data;}catch(e){return;}if(data&&data.type==='WA_EMBEDDED_SIGNUP'){waSessionInfo=data.data||data;document.getElementById('waSession').textContent=JSON.stringify(waSessionInfo,null,2);document.getElementById('waStatus').textContent='Signup session info प्राप्त हुआ। Token exchange अभी server-side सेट करना बाकी है।';}});
function fbLoginCallback(response){if(response&&response.authResponse&&response.authResponse.code){document.getElementById('waStatus').textContent='Authorization code प्राप्त हुआ। सुरक्षित token exchange के लिए server endpoint configure करना आवश्यक है।';/* Never expose app secret or exchange token in browser. */}else{document.getElementById('waStatus').textContent='Signup पूरा नहीं हुआ या अनुमति नहीं मिली।';}}
document.getElementById('waSignupBtn').addEventListener('click',function(){if(!window.FB){document.getElementById('waStatus').textContent='Meta SDK अभी तैयार नहीं है। पेज refresh करके फिर कोशिश करें।';return;}FB.login(fbLoginCallback,{config_id:'29735247966059908',response_type:'code',override_default_response_type:true,extras:{version:'v4',setup:{}}});});
</script></body></html><?php
    exit;
}
elseif($route==='whatsapp-bulk'){ $_GET['tab']='bulk'; $route='whatsapp-center'; }

// Public read-only metadata consumed by the Android app. No member/payment data is returned.
if ($route === 'app-update-check') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $releaseFile = basename(getSetting('app_update_apk_filename', ''));
    $releasePath = $releaseFile !== '' ? __DIR__ . '/uploads/app-releases/' . $releaseFile : '';
    $hasApk = $releasePath !== '' && is_file($releasePath);
    $release = [
        'enabled' => getSetting('app_update_enabled', '0') === '1' && $hasApk,
        'versionName' => getSetting('app_update_version_name', '1.0.0'),
        'versionCode' => max(1, (int)getSetting('app_update_version_code', '1')),
        'minimumVersionCode' => max(1, (int)getSetting('app_update_min_version_code', '1')),
        'apkUrl' => $hasApk ? siteBaseUrl() . '/?route=app-release-download' : '',
        'releaseNotes' => getSetting('app_update_release_notes', ''),
        'logoUrl' => assetUrl(brandingAssetSetting('header_logo', 'assets/logo.png')),
    ];
    echo json_encode($release, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// APK downloads use a server-controlled basename; the APK files are never served from arbitrary paths.
if ($route === 'app-release-download') {
    $releaseFile = basename(getSetting('app_update_apk_filename', ''));
    $releasePath = $releaseFile !== '' ? __DIR__ . '/uploads/app-releases/' . $releaseFile : '';
    if ($releasePath === '' || !is_file($releasePath)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        exit('GS Suraha APK is not available yet.');
    }
    header('Content-Type: application/vnd.android.package-archive');
    header('Content-Disposition: attachment; filename="GS-Suraha.apk"');
    header('Content-Length: ' . filesize($releasePath));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    readfile($releasePath);
    exit;
}

// Release management is restricted to the existing Super Admin account.
if ($route === 'app-release-admin') {
    requireRole(['admin']);
    if (!isSuperAdmin()) { http_response_code(403); exit('Super Admin permission required'); }
    $msg = '';
    $err = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $versionName = trim((string)($_POST['version_name'] ?? ''));
        $versionCode = filter_var($_POST['version_code'] ?? null, FILTER_VALIDATE_INT);
        $minimumVersionCode = filter_var($_POST['minimum_version_code'] ?? '1', FILTER_VALIDATE_INT);
        $releaseNotes = trim(strip_tags((string)($_POST['release_notes'] ?? '')));
        if ($versionName === '' || strlen($versionName) > 40 || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._+-]*$/', $versionName)) {
            $err = 'Version name 1.0.0 जैसे format में दें (अधिकतम 40 characters)।';
        } elseif ($versionCode === false || $versionCode < 1 || $minimumVersionCode === false || $minimumVersionCode < 1 || $minimumVersionCode > $versionCode) {
            $err = 'Version code और minimum version code सही positive number होने चाहिए; minimum, latest version से बड़ा नहीं हो सकता।';
        } elseif (strlen($releaseNotes) > 3000) {
            $err = 'Release notes 3000 characters से कम रखें।';
        } else {
            $apk = $_FILES['apk_file'] ?? null;
            $newFilename = '';
            if ($apk && (int)($apk['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                if ((int)$apk['error'] !== UPLOAD_ERR_OK || (int)$apk['size'] < 1024 || (int)$apk['size'] > 200 * 1024 * 1024) {
                    $err = 'APK upload पूरा नहीं हुआ या file 200 MB से बड़ी है।';
                } else {
                    $tmp = (string)$apk['tmp_name'];
                    $head = file_get_contents($tmp, false, null, 0, 4);
                    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
                    if (strtolower(pathinfo((string)$apk['name'], PATHINFO_EXTENSION)) !== 'apk' || $head !== "PK\x03\x04" || !in_array($mime, ['application/zip', 'application/vnd.android.package-archive', 'application/octet-stream'], true)) {
                        $err = 'सिर्फ valid Android APK file upload करें।';
                    } else {
                        $dir = __DIR__ . '/uploads/app-releases';
                        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) $err = 'APK folder नहीं बन पाया; hosting folder permissions जाँचें।';
                        else {
                            $newFilename = 'gs-suraha-v' . (int)$versionCode . '-' . date('YmdHis') . '-' . bin2hex(random_bytes(4)) . '.apk';
                            if (!move_uploaded_file($tmp, $dir . '/' . $newFilename)) $err = 'APK server पर save नहीं हो पाई।';
                        }
                    }
                }
            }
            $currentVersionCode = (int)getSetting('app_update_version_code', '1');
            if ($err === '' && (int)$versionCode !== $currentVersionCode && $newFilename === '') {
                $err = 'Version code बदलने पर उसी version का नया APK upload करना ज़रूरी है।';
            }
            if ($err === '') {
                setSetting('app_update_version_name', $versionName);
                setSetting('app_update_version_code', (string)(int)$versionCode);
                setSetting('app_update_min_version_code', (string)(int)$minimumVersionCode);
                setSetting('app_update_release_notes', $releaseNotes);
                setSetting('app_update_enabled', isset($_POST['enabled']) ? '1' : '0');
                if ($newFilename !== '') setSetting('app_update_apk_filename', $newFilename);
                audit('app_release_updated', 'Version ' . $versionName . ' (' . (int)$versionCode . '), APK ' . ($newFilename !== '' ? 'uploaded' : 'unchanged'));
                $msg = 'App release settings save हो गईं। पुराने APK files को हटाया नहीं गया।';
            }
        }
    }
    $versionName = getSetting('app_update_version_name', '1.0.0');
    $versionCode = getSetting('app_update_version_code', '1');
    $minimumVersionCode = getSetting('app_update_min_version_code', '1');
    $releaseNotes = getSetting('app_update_release_notes', '');
    $enabled = getSetting('app_update_enabled', '0') === '1';
    $currentApk = basename(getSetting('app_update_apk_filename', ''));
    ob_start(); ?>
    <style>.app-release-wrap{max-width:850px;margin:20px auto}.app-release-wrap .panel{padding:22px}.app-release-wrap label{display:block;font-weight:700;margin:14px 0 6px}.app-release-wrap input,.app-release-wrap textarea{width:100%;padding:11px;border:1px solid #d5dfd7;border-radius:10px}.app-release-wrap .release-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.app-release-wrap .muted{line-height:1.65}.app-release-wrap .check-row{display:flex;align-items:center;gap:10px;margin:16px 0}.app-release-wrap .check-row input{width:auto}@media(max-width:650px){.app-release-wrap .release-grid{grid-template-columns:1fr}}</style>
    <div class="app-release-wrap"><div class="page-title"><div><div class="eyebrow">SUPER ADMIN</div><h1>📱 Android App Release</h1><p>APK version publish/update करें। पुराने member और payment data को नहीं छुआ जाता।</p></div><a class="btn" href="?route=control-center">← Control Center</a></div>
    <?php if ($msg !== ''): ?><div class="alert success">✅ <?=h($msg)?></div><?php endif; ?>
    <?php if ($err !== ''): ?><div class="alert danger">⚠️ <?=h($err)?></div><?php endif; ?>
    <div class="panel"><h2>Latest app release</h2><p class="muted">Current setting: <b><?=h($versionName)?></b> · version code <b><?=h($versionCode)?></b> · <?= $enabled ? 'Update prompt ON' : 'Update prompt OFF' ?></p><p class="muted">Current APK file: <?= $currentApk !== '' ? h($currentApk) : 'अभी कोई APK upload नहीं है' ?></p>
    <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>">
      <div class="release-grid"><div><label>Version name</label><input name="version_name" value="<?=h($versionName)?>" maxlength="40" placeholder="1.0.1" required></div><div><label>Version code (हर release पर बढ़ाएँ)</label><input type="number" name="version_code" min="1" value="<?=h($versionCode)?>" required></div></div>
      <label>Minimum supported version code (optional enforcement)</label><input type="number" name="minimum_version_code" min="1" value="<?=h($minimumVersionCode)?>" required>
      <label>नया APK upload करें (200 MB तक; signing key/package वही होना चाहिए)</label><input type="file" name="apk_file" accept=".apk,application/vnd.android.package-archive">
      <label>Release notes</label><textarea name="release_notes" rows="4" maxlength="3000" placeholder="इस update में क्या नया है?"><?=h($releaseNotes)?></textarea>
      <label class="check-row"><input type="checkbox" name="enabled" value="1" <?=$enabled?'checked':''?>> APK upload हो और release तैयार हो तो app खोलने पर update prompt दिखाएँ</label>
      <button class="btn primary" type="submit">💾 Release settings save करें</button>
    </form></div>
    <div class="panel"><h2>App logo और launcher icon</h2><p class="muted">App के andar dikhne wala logo तुरंत बदलने के लिए Control Center → Branding में website का header logo बदलें। Android home-screen launcher icon APK में bundled होता है; नया icon लगाने के लिए updated icon के साथ APK rebuild करके ऊपर upload करें। Android install confirmation user को ही करनी होती है।</p><a class="btn" href="?route=control-center&tab=branding">🖼️ Website logo settings खोलें</a></div></div>
    <?php $content = ob_get_clean(); layout('Android App Release', $content); exit;
}

// Public app download page. Works without login so the WhatsApp welcome link is usable by new members.
if($route==='download-app' || $route==='download') {
    $apkPath=__DIR__.'/downloads/GS-Suraha.apk';
    if(!is_file($apkPath)){
        http_response_code(404);
        ?><!doctype html><html lang="hi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>App Download</title></head><body style="font-family:Arial,sans-serif;padding:30px;text-align:center"><h2>GS Suraha App</h2><p>APK अभी server पर upload नहीं है।</p><p><b>downloads/GS-Suraha.apk</b> upload करें।</p></body></html><?php
        exit;
    }
    header('Content-Type: application/vnd.android.package-archive');
    header('Content-Disposition: attachment; filename="GS-Suraha.apk"');
    header('Content-Length: '.filesize($apkPath));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    readfile($apkPath);
    exit;
}

// Public reference-style landing page. The original login route remains unchanged at ?route=login.
if($route==='home'){
    $siteName=getSetting('site_name',getSetting('society_name','GS Suraha Sahyog Samiti'));
    $tagline=getSetting('society_tagline','Finance Co-operative Society');
    $heroLoginSide=in_array(getSetting('front_hero_side','right'),['right','left'],true)?getSetting('front_hero_side','right'):'right'; $heroSide=($heroLoginSide==='right'?'left':'right');
    $frontHeaderBg=getSetting('front_header_bg_color','#ffffff'); if(!preg_match('/^#[0-9a-fA-F]{6}$/',$frontHeaderBg)) $frontHeaderBg='#ffffff';
    $frontHeaderBgTransparent=getSetting('front_header_bg_transparent','0')==='1';
    $frontHeaderText=getSetting('front_header_text_color','#075c37'); if(!preg_match('/^#[0-9a-fA-F]{6}$/',$frontHeaderText)) $frontHeaderText='#075c37';
    $frontHeaderAccent=getSetting('front_header_accent_color','#08783e'); if(!preg_match('/^#[0-9a-fA-F]{6}$/',$frontHeaderAccent)) $frontHeaderAccent='#08783e';
    $bannerPosition=in_array(getSetting('front_banner_position','left'),['left','center','right'],true)?getSetting('front_banner_position','left'):'left';
    $bannerOverlay=getSetting('front_banner_overlay','light');
    $bannerGradients=['light'=>'linear-gradient(90deg,rgba(255,255,255,0) 25%,rgba(255,255,255,.78) 68%,rgba(255,255,255,.96) 100%)','green'=>'linear-gradient(90deg,rgba(4,55,32,.08) 20%,rgba(4,85,47,.84) 100%)','blue'=>'linear-gradient(90deg,rgba(7,27,60,.06) 20%,rgba(7,42,91,.82) 100%)','none'=>'linear-gradient(90deg,rgba(255,255,255,0),rgba(255,255,255,0))'];
    if(!isset($bannerGradients[$bannerOverlay])) $bannerOverlay='light';
    $bannerGradient=$bannerGradients[$bannerOverlay];
    $frontColorDefaults=['front_hero_title_color'=>in_array($bannerOverlay,['green','blue'],true)?'#ffffff':'#006132','front_hero_slogan_color'=>'#064d2d','front_login_heading_color'=>'#075d35','front_member_login_color'=>'#075c37','front_admin_login_color'=>'#075c37'];
    $frontTextColors=[]; foreach($frontColorDefaults as $colorKey=>$colorDefault){$colorValue=getSetting($colorKey,$colorDefault);$frontTextColors[$colorKey]=preg_match('/^#[0-9a-fA-F]{6}$/',$colorValue)?strtoupper($colorValue):strtoupper($colorDefault);}
    $heroTitleColor=$frontTextColors['front_hero_title_color']; $heroSloganColor=$frontTextColors['front_hero_slogan_color']; $loginHeadingColor=$frontTextColors['front_login_heading_color']; $memberLoginColor=$frontTextColors['front_member_login_color']; $adminLoginColor=$frontTextColors['front_admin_login_color'];
    $phone=getSetting('contact_phone','+91 98765 43210');
    $email=getSetting('contact_email','info@gssuraha.in');
    $address=getSetting('contact_address','GS Suraha Sahyog Samiti');
    $heroImage=brandingAssetSetting('front_hero_image','assets/gs-suraha-hero.jpg');
    $configuredHeaderArtwork=trim(getSetting('front_header_image',''));
    $headerArtwork=brandingAssetSetting('front_header_image','assets/front-header-test.png');
    $headerArtworkUrl=$headerArtwork!==''?assetUrl($headerArtwork):'';
    $headerArtworkFit=in_array(getSetting('front_header_image_fit','cover'),['contain','cover','auto'],true)?getSetting('front_header_image_fit','cover'):'cover';
    if($configuredHeaderArtwork==='' || $headerArtwork==='assets/front-header-test.png') $headerArtworkFit='cover';
    $headerTestMode=isset($_GET['header_test']) && (string)$_GET['header_test']==='1';
    if($headerTestMode){$headerArtwork='assets/front-header-test.png';$headerArtworkUrl=assetUrl($headerArtwork);$headerArtworkFit='cover';}
    $headerArtworkOnly=getSetting('front_header_artwork_only','0')==='1';
    $brandNameSize=max(12,min(48,(int)getSetting('front_brand_name_size','28')));
    $brandTaglineSize=max(8,min(24,(int)getSetting('front_brand_tagline_size','17')));
    $homeMembers=[]; $hq=$db->query("SELECT id,code,name,photo,status FROM members ORDER BY id DESC LIMIT 40");
    while($hq && ($hm=$hq->fetchArray(SQLITE3_ASSOC))) $homeMembers[]=$hm;
    $homeNotices=[];
    // v209_ui6: running/chalti notice on front page disabled as requested
    if(false && getSetting('notice_enabled','1')==='1'){
        $nq=$db->query("SELECT title,body,created_at FROM notices WHERE enabled=1 ORDER BY id DESC");
        while($nq && ($hn=$nq->fetchArray(SQLITE3_ASSOC))) $homeNotices[]=$hn;
        $staticHomeNotice=trim(getSetting('notice_text',''));
        if($staticHomeNotice!=='') array_unshift($homeNotices,['title'=>'महत्वपूर्ण सूचना','body'=>$staticHomeNotice,'created_at'=>date('Y-m-d H:i:s')]);
    }
    $homeContributionActivity=[];
    $hca=$db->query("SELECT created_at FROM contributions WHERE status='Paid' ORDER BY id DESC LIMIT 8");
    while($hca && ($hc=$hca->fetchArray(SQLITE3_ASSOC))) $homeContributionActivity[]=$hc;
    $latestContributionTitle=getSetting('front_latest_contribution_title','Latest Contribution');
    $latestContributionTemplate=getSetting('front_latest_contribution_template','A member contribution was received on {date} — thank you for supporting {site}.');
    $latestContributionEmpty=getSetting('front_latest_contribution_empty','Member contributions help strengthen our community and support society services.');
    ob_start(); ?>
    <style>
      .home-page{font-family:Arial,Helvetica,sans-serif;background:#f5fbf7;color:#10251d;min-height:100vh}.home-page *{box-sizing:border-box}.home-top{background:#005b35;color:#fff;display:flex;justify-content:space-between;align-items:center;gap:18px;padding:8px clamp(14px,3vw,32px);font-size:14px;font-weight:700}.home-top-left,.home-top-right{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.home-top span{display:inline-flex;align-items:center;gap:6px}.home-top strong{font-size:16px}.home-nav{background:var(--front-header-bg,#fff);display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:var(--front-header-height,76px);padding:8px clamp(14px,3vw,38px);box-shadow:0 2px 10px rgba(4,68,38,.12);position:relative;z-index:2}.home-brand{display:flex;align-items:center;gap:13px;color:#075c37;min-width:270px}.home-brand img{width:var(--front-logo-size,72px);height:var(--front-logo-size,72px);object-fit:contain}.home-brand b{font-size:28px;line-height:1.04;display:block}.home-brand small{font-size:17px;font-weight:700}.home-links{display:flex;align-items:center;gap:7px;flex-wrap:wrap;justify-content:flex-end}.home-links a{color:var(--front-header-text,#142018);text-decoration:none;font-weight:700;font-size:var(--front-nav-font-size,12px);padding:var(--front-nav-item-padding,7px) 10px;border-radius:8px;white-space:nowrap}.home-links a:hover,.home-links a.home-active{background:var(--front-header-accent,#08783e);color:#fff}.home-hero{min-height:365px;background-image:<?=$bannerGradient?>,url('<?=h($heroImage)?>');background-size:cover;background-position:<?=$bannerPosition?> center;display:grid;grid-template-columns:minmax(0,1fr) minmax(280px,390px);align-items:center;gap:20px;padding:28px clamp(16px,3vw,38px)}.home-hero-copy{padding:10px 0 10px 58%;max-width:none}.home-hero-copy h1{font-family:Georgia,serif;color:#006132;font-size:clamp(30px,3.2vw,46px);line-height:.98;margin:0 0 16px;max-width:390px}.home-hero-copy p{width:420px;display:inline-block;background:rgba(0,112,53,.92);color:#fff;border-radius:28px;padding:12px 24px;font-size:clamp(18px,2vw,27px);font-weight:700;margin:0;box-shadow:0 8px 20px rgba(0,65,29,.18)}.home-hero-copy .home-swoosh{height:8px;width:310px;margin:16px 0 0 30px;background:linear-gradient(90deg,#f28c28 0 34%,#fff 34% 57%,#078543 57%);border-radius:100%;transform:skewX(-25deg)}.home-login-card{background:rgba(255,255,255,.96);border-radius:15px;padding:16px;box-shadow:0 8px 24px rgba(8,62,35,.18);border:1px solid rgba(0,102,52,.12)}.home-login-card h2{margin:0 0 12px;color:#075d35;font-size:20px}.home-login-card a{display:flex;justify-content:space-between;align-items:center;text-decoration:none;color:#fff;padding:14px 16px;border-radius:10px;margin:10px 0;font-size:20px;font-weight:700}.home-login-member{background:#13a14b}.home-login-admin{background:#1474ce}.home-login-card h3{background:#078242;color:#fff;text-align:center;border-radius:8px;padding:10px;margin:16px 0 8px;font-size:16px}.home-login-card ul{list-style:none;padding:0;margin:0}.home-login-card li{padding:5px 0;font-size:14px}.home-login-card li:before{content:'✓';color:#088546;font-weight:900;margin-right:9px}.home-section-grid{display:grid;grid-template-columns:1.1fr .95fr;gap:20px;padding:20px clamp(14px,3vw,32px)}.home-panel{background:#fff;border-radius:13px;box-shadow:0 3px 13px rgba(12,67,38,.12);overflow:hidden}.home-panel-head{background:#08753c;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 16px}.home-panel-head h2{font-size:23px;margin:0}.home-panel-head a{background:#b9ebff;color:#064b36;border-radius:18px;padding:7px 14px;text-decoration:none;font-weight:700;font-size:13px}.home-members{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:14px}.home-member{text-align:center;border:1px solid #e0ebe4;border-radius:10px;overflow:hidden;background:#fbfffc}.home-member-photo{height:150px;background:linear-gradient(135deg,#edf5f0,#dbeee0);display:flex;align-items:center;justify-content:center}.home-member-photo img{width:100%;height:100%;object-fit:cover}.home-member-photo span{font-size:58px}.home-photo-fallback{display:flex;align-items:center;justify-content:center;width:100%;height:100%}.home-member b{display:block;font-size:16px;padding:9px 5px 1px}.home-member small{display:block;padding:0 5px 10px;color:#506359}.home-notices{padding:8px 16px 12px}.home-notice{display:grid;grid-template-columns:35px 1fr auto;gap:10px;align-items:center;padding:13px 0;border-bottom:1px solid #e6eee8}.home-notice:last-child{border-bottom:0}.home-notice-icon{font-size:22px}.home-notice b{font-size:16px}.home-notice p{margin:3px 0 0;color:#64756a;font-size:13px}.home-notice time{font-size:12px;color:#68766d;white-space:nowrap}.home-empty{padding:24px;color:#6c7d73}.home-features{margin:0 clamp(14px,3vw,32px) 18px;padding:14px 20px;background:#dff7df;border-radius:14px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px;color:#075f38}.home-feature{display:flex;align-items:center;justify-content:center;gap:10px;border-right:1px solid #72b982;font-weight:800;text-align:center}.home-feature:last-child{border-right:0}.home-feature span{font-size:30px}.home-footer{background:#005c35;color:#fff;display:flex;justify-content:space-between;gap:15px;padding:18px clamp(14px,3vw,32px);font-weight:700}.home-footer a{color:#fff;margin-left:14px}.home-footer small{font-weight:400}@media(max-width:1050px){.home-hero-copy{padding-left:34%}.home-brand b{font-size:23px}.home-brand small{font-size:14px}.home-links a{padding:10px 9px}.home-hero{grid-template-columns:1fr 320px}.home-section-grid{grid-template-columns:1fr}}@media(max-width:720px){.home-top{font-size:11px}.home-top-right{display:none}.home-nav{align-items:flex-start}.home-brand{min-width:0}.home-brand img{width:53px;height:53px}.home-brand b{font-size:18px}.home-brand small{font-size:12px}.home-links{gap:3px}.home-links a{font-size:11px;padding:8px 6px}.home-links a:nth-child(n+3){display:none}.home-hero{display:block;min-height:560px;background-image:linear-gradient(180deg,rgba(255,255,255,0) 20%,rgba(255,255,255,.88) 62%,rgba(255,255,255,.98) 100%),url('<?=h($heroImage)?>');padding:18px 14px}.home-hero-copy{padding:14px 8px 135px}.home-hero-copy h1{font-size:39px}.home-hero-copy p{font-size:16px;padding:10px 15px}.home-login-card{max-width:390px;margin:-120px auto 0;position:relative}.home-section-grid{padding:14px 10px;gap:14px}.home-panel-head h2{font-size:18px}.home-members{grid-template-columns:repeat(2,1fr);gap:8px}.home-member-photo{height:126px}.home-notice{grid-template-columns:25px 1fr}.home-notice time{display:none}.home-features{grid-template-columns:repeat(2,1fr);margin:0 10px 14px;padding:12px 6px}.home-feature{border-right:0;font-size:12px}.home-feature span{font-size:23px}.home-footer{display:block;text-align:center;font-size:13px}.home-footer small{display:block;margin-top:8px}}

      /* Mobile-only homepage redesign. Desktop rules above are intentionally untouched. */
      .home-member-slider{position:relative}
      .home-member-arrow{display:none}
      .home-notice-track{display:block}
      @media(max-width:720px){
        .home-page .home-top-right{display:none!important;visibility:hidden!important;height:0!important;overflow:hidden!important}
        .home-page{padding-bottom:0;background:#f1f6fb;overflow:hidden}
        .home-top{padding:6px 12px;font-size:10px}
        .home-top-left{gap:8px}
        .home-nav{padding:9px 12px;align-items:center;gap:8px}
        .home-brand{gap:8px}
        .home-brand img{width:48px;height:48px}
        .home-brand b{font-size:17px;white-space:normal}
        .home-brand small{font-size:11px}
        .home-links{gap:3px}
        .home-links a{font-size:10px;padding:7px 6px}
        .home-links a:nth-child(n+3){display:none}
        .home-hero{min-height:0;display:flex;flex-direction:column;gap:12px;padding:20px 13px 14px;background-image:linear-gradient(180deg,rgba(0,75,39,.18),rgba(255,255,255,.94) 65%),url('<?=h($heroImage)?>');background-position:center;background-size:cover}
        .home-hero-copy{padding:8px 5px 0;width:100%;text-align:center}
        .home-hero-copy h1{font-size:29px;line-height:1.12;max-width:none;margin:0 auto 10px;color:#075d35;text-shadow:0 1px 2px #fff}
        .home-hero-copy p{width:auto;max-width:100%;font-size:15px;line-height:1.4;padding:9px 13px;border-radius:14px}
        .home-hero-copy .home-swoosh{width:150px;height:5px;margin:10px auto}
        .home-login-card{width:100%;max-width:none;margin:0;position:static;padding:12px;border-radius:13px}
        .home-login-card h2{font-size:17px;text-align:center;margin-bottom:8px}
        .home-login-card>a{display:inline-flex;width:calc(50% - 6px);justify-content:center;gap:5px;padding:12px 6px;margin:4px 2px;font-size:14px}
        .home-login-card h3,.home-login-card ul{display:none}
        .home-section-grid{display:flex;flex-direction:column;gap:13px;padding:12px 10px}
        .home-notice-panel{order:-1}
        .home-panel{border-radius:13px}
        .home-panel-head{padding:10px 12px}
        .home-panel-head h2{font-size:16px;line-height:1.25}
        .home-panel-head a{font-size:11px;padding:6px 9px;white-space:nowrap}
        .home-notices{height:58px;padding:0 10px;overflow:hidden;display:flex;align-items:center}
        .home-notice-track{width:100%;animation:gsNoticeUp 12s linear infinite}
        .home-notice-track:hover{animation-play-state:paused}
        .home-notice{display:flex;align-items:center;gap:9px;width:100%;min-height:58px;padding:8px 0;border-bottom:1px solid #e6eee8}
        .home-notice-icon{font-size:20px;flex:0 0 24px}
        .home-notice>div{min-width:0;flex:1}
        .home-notice b{font-size:13px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#075d35}
        .home-notice p{font-size:11px;line-height:1.3;margin:3px 0 0;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
        .home-notice time{display:none}
        @keyframes gsNoticeUp{0%,12%{transform:translateY(0)}20%,32%{transform:translateY(-58px)}40%,52%{transform:translateY(-116px)}60%,72%{transform:translateY(-174px)}80%,100%{transform:translateY(0)}}
        .home-member-slider{position:relative;padding:0 30px}
        .home-members{display:flex;gap:10px;padding:12px 2px;overflow-x:auto;scroll-behavior:smooth;scroll-snap-type:x mandatory;scrollbar-width:none;-webkit-overflow-scrolling:touch}
        .home-members::-webkit-scrollbar{display:none}
        .home-member{flex:0 0 46%;scroll-snap-align:start;border-radius:12px;box-shadow:0 2px 8px rgba(12,67,38,.10)}
        .home-member-photo{height:125px}
        .home-member b{font-size:14px;padding:8px 4px 1px}
        .home-member small{font-size:11px;padding-bottom:8px}
        .home-member-arrow{display:flex;position:absolute;z-index:2;top:50%;transform:translateY(-50%);width:29px;height:38px;border:0;border-radius:20px;background:#08783e;color:#fff;font-size:27px;line-height:1;align-items:center;justify-content:center;box-shadow:0 2px 7px #0002}
        .home-member-prev{left:2px}.home-member-next{right:2px}
        .home-about{display:block!important;margin:0 10px 14px!important;padding:15px!important}
        .home-about #contact{border-left:0!important;border-top:1px solid #d6e8da;padding:12px 0 0!important;margin-top:12px}
        .home-features{grid-template-columns:repeat(2,minmax(0,1fr));margin:0 10px 14px;padding:12px 6px;gap:10px}
        .home-feature{border:0;font-size:11px;line-height:1.3}
        .home-feature span{font-size:22px}
        .home-footer{display:block;text-align:center;padding:15px 10px;font-size:12px}
        .home-footer small{display:block;margin-top:8px}
      }
      @media(max-width:720px){.home-contribution{margin:0 8px 12px!important;padding:12px!important;gap:10px!important}.home-contribution h2{font-size:15px!important}.home-contribution p{font-size:12px!important}.home-contribution a{font-size:12px!important;padding:9px 12px!important}}
      @media(max-width:380px){.home-brand b{font-size:15px}.home-brand img{width:42px;height:42px}.home-login-card>a{font-size:12px}.home-member{flex-basis:49%}.home-member-photo{height:110px}}

      /* V91: reliable mobile member/notice sliders, four newest cards and uncropped photos. */
      @media(max-width:720px){
        .home-page .home-contribution{display:none!important}
        .home-page .home-members{display:flex!important;flex-wrap:nowrap!important;overflow-x:auto!important;scroll-snap-type:x mandatory!important;scroll-behavior:smooth!important;gap:8px!important}
        .home-page .home-member{flex:0 0 calc(50% - 4px)!important;scroll-snap-align:start!important;min-width:0!important}
        .home-page .home-member-photo{height:112px!important;padding:4px!important}
        .home-page .home-member-photo img{width:100%!important;height:100%!important;object-fit:contain!important;object-position:center!important}
        .home-page .home-notices{height:auto;max-height:none!important;overflow:hidden!important;display:block!important}
        .home-page .home-notice-track{width:100%!important;animation:none!important;transform:translateY(0);transition:transform .65s ease!important}
        .home-page .home-notice{display:flex!important;min-height:0!important;align-items:flex-start!important}
        .home-page .home-notice p{display:block!important;-webkit-line-clamp:unset!important;overflow:visible!important;white-space:normal!important}
      }
      /* V90: modern newest-first member cards and gentle auto-sliding carousel. */
      .home-member{position:relative;border:1px solid #d8e9de!important;border-radius:15px!important;background:linear-gradient(180deg,#fff,#f7fcf8)!important;box-shadow:0 5px 16px rgba(7,82,43,.10);transition:transform .25s ease,box-shadow .25s ease}
      .home-member:hover{transform:translateY(-3px);box-shadow:0 10px 22px rgba(7,82,43,.16)}
      .home-member-photo{position:relative;overflow:hidden;background:linear-gradient(135deg,#dff2e5,#f1faf4)!important}
      .home-member-photo img{transition:transform .35s ease}
      .home-member:hover .home-member-photo img{transform:scale(1.04)}
      .home-member-new-badge{position:absolute!important;z-index:1;top:8px;left:8px;background:linear-gradient(110deg,#ff9b32,#f2633c);color:#fff!important;border-radius:20px;padding:5px 9px;font-size:11px!important;font-weight:800;box-shadow:0 2px 7px #0002}
      .home-member-slider{overflow:hidden}
      .home-members{scrollbar-width:none}
      .home-members::-webkit-scrollbar{display:none}
      @media(prefers-reduced-motion:reduce){.home-member,.home-member-photo img{transition:none!important}}
      /* V89: remove redundant top strip and keep every homepage notice readable. */
      .home-page .home-top{display:none!important}
      .home-page .home-notices{height:auto!important;max-height:none!important;overflow:visible!important;display:block!important}
      .home-page .home-notice-track{animation:none!important;transform:none!important}
      .home-page .home-notice{align-items:start}
      .home-page .home-notice p{white-space:normal;overflow:visible}
      @media(max-width:720px){.home-page .home-notices{height:auto!important;max-height:none!important;overflow:visible!important}.home-page .home-notice-track{animation:none!important;transform:none!important}.home-page .home-notice{min-height:0!important}.home-page .home-notice p{display:block!important;-webkit-line-clamp:unset!important;overflow:visible!important}}
      /* V79: compact mobile home and remove the coloured body area after the footer. Desktop remains unchanged. */
      @media(max-width:720px){
        html:has(.home-page),body:has(.home-page){background:#f1f6fb!important;margin:0!important;padding:0!important;min-height:0!important;}
        body:has(.home-page){overflow-x:hidden!important;}
        .home-page{display:flex!important;flex-direction:column!important;min-height:100svh!important;height:auto!important;padding:0 0 env(safe-area-inset-bottom)!important;margin:0!important;background:#f1f6fb!important;overflow:hidden!important;}
        .home-top{min-height:30px!important;padding:5px 10px!important;}
        .home-nav{min-height:58px!important;padding:6px 10px!important;}
        .home-brand img{width:42px!important;height:42px!important;}
        .home-brand b{font-size:16px!important;}
        .home-brand small{font-size:10px!important;}
        .home-hero{min-height:0!important;padding:12px 10px!important;gap:8px!important;background-position:center!important;}
        .home-hero-copy{padding:2px 4px 0!important;}
        .home-hero-copy h1{font-size:24px!important;line-height:1.12!important;margin-bottom:6px!important;}
        .home-hero-copy p{font-size:13px!important;line-height:1.3!important;padding:7px 10px!important;}
        .home-hero-copy .home-swoosh{margin:6px auto!important;height:4px!important;}
        /* V80: show the hero photo around the Member/Admin login controls on mobile only. */
        .home-login-card{padding:8px 10px!important;background:transparent!important;border:1px solid transparent!important;box-shadow:none!important;}
        .home-login-card h2{color:#075d35!important;text-shadow:0 1px 3px rgba(255,255,255,.85)!important;}

        .home-login-card h2{font-size:14px!important;margin:0 0 5px!important;}
        .home-login-card>a{padding:8px 5px!important;margin:3px 1px!important;font-size:12px!important;min-height:36px!important;}
        .home-section-grid{padding:8px 8px!important;gap:8px!important;}
        .home-panel-head{padding:7px 9px!important;}
        .home-panel-head h2{font-size:14px!important;}
        .home-panel-head a{font-size:10px!important;padding:5px 7px!important;}
        /* V85: keep the hero photo visible; make the slogan transparent and right-aligned on mobile. */
        .home-hero{background-image:linear-gradient(180deg,rgba(0,75,39,.08),rgba(255,255,255,.24) 65%),url('<?=h($heroImage)?>')!important;background-position:center!important;background-size:cover!important;}
        .home-hero-copy{width:100%!important;text-align:right!important;display:flex!important;flex-direction:column!important;align-items:flex-end!important;}
        .home-hero-copy h1{width:100%!important;text-align:right!important;}
        .home-hero-copy p{width:auto!important;max-width:100%!important;display:inline-block!important;background:transparent!important;color:#064d2d!important;border:0!important;border-radius:0!important;box-shadow:none!important;padding:5px 0!important;text-align:right!important;text-shadow:0 1px 3px rgba(255,255,255,.9)!important;}
        .home-hero-copy .home-swoosh{margin:6px 0 0 auto!important;}
        /* Show every active notice; mobile users can scroll the full list instead of a four-item ticker. */
        .home-notices{height:auto!important;max-height:360px!important;overflow-y:auto!important;overflow-x:hidden!important;display:block!important;padding:0 8px!important;}
        .home-notice-track{width:100%!important;animation:none!important;transform:none!important;}
        .home-notice{min-height:48px!important;padding:7px 0!important;gap:6px!important;}
        .home-notice p{display:block!important;-webkit-line-clamp:unset!important;overflow:visible!important;}

        .home-notice-icon{font-size:17px!important;flex-basis:20px!important;}
        .home-notice b{font-size:12px!important;}
        .home-notice p{font-size:10px!important;margin-top:1px!important;}
        @keyframes gsNoticeUp{0%,12%{transform:translateY(0)}20%,32%{transform:translateY(-48px)}40%,52%{transform:translateY(-96px)}60%,72%{transform:translateY(-144px)}80%,100%{transform:translateY(0)}}
        .home-member-slider{padding:0 25px!important;}
        .home-members{gap:7px!important;padding:8px 2px!important;}
        .home-member{flex-basis:43%!important;}
        .home-member-photo{height:88px!important;}
        .home-member b{font-size:11px!important;padding:5px 3px 0!important;}
        .home-member small{font-size:9px!important;padding:0 3px 5px!important;}
        .home-member-arrow{width:24px!important;height:32px!important;font-size:22px!important;}
        .home-about{margin:0 8px 8px!important;padding:10px 11px!important;gap:8px!important;}
        .home-about h2{font-size:16px!important;margin-bottom:4px!important;}
        .home-about p{font-size:11px!important;line-height:1.4!important;}
        .home-about #contact{padding-top:7px!important;margin-top:7px!important;}
        .home-about #contact p{margin:3px 0!important;}
        .home-features{margin:0 8px 8px!important;padding:8px 5px!important;gap:5px!important;}
        .home-feature{font-size:10px!important;gap:5px!important;line-height:1.2!important;}
        .home-feature span{font-size:17px!important;}
        /* V81: remove the artificial full-screen stretch/white tail on mobile; keep footer compact. */
        html:has(.home-page),body:has(.home-page){background:#005c35!important;min-height:0!important;height:auto!important;}
        .home-page{min-height:0!important;height:auto!important;flex:0 0 auto!important;padding-bottom:0!important;background:#f1f6fb!important;}
        .home-footer{margin-top:0!important;padding:6px 7px!important;min-height:0!important;font-size:9px!important;line-height:1.2!important;gap:4px!important;}
        .home-footer a{margin-left:8px!important;}
        .home-footer small{font-size:8px!important;margin-top:2px!important;line-height:1.2!important;}
        .home-login-card>a{min-height:34px!important;padding:6px 7px!important;margin:2px 1px!important;gap:6px!important;border-radius:10px!important;}
        .home-login-icon{width:19px!important;height:19px!important;flex:0 0 19px!important;fill:none!important;stroke:currentColor!important;stroke-width:1.8!important;stroke-linecap:round!important;stroke-linejoin:round!important;}
        .home-login-label{font-size:12px!important;font-weight:800!important;}
        .home-login-arrow{font-size:18px!important;line-height:1!important;margin-left:auto!important;}
      }
      @media(max-width:380px){
        .home-hero-copy h1{font-size:21px!important;}
        .home-member{flex-basis:46%!important;}
        .home-member-photo{height:78px!important;}
      }

      /* V82: eliminate the mobile-only blank tail, compact notice heading and keep contact details on two clear lines. */
      @media(max-width:720px){
        html:has(.home-page){height:auto!important;min-height:0!important;background:#005c35!important;}
        body.login-page:has(.home-page){display:block!important;width:100%!important;height:auto!important;min-height:0!important;margin:0!important;padding:0!important;overflow-x:hidden!important;overflow-y:auto!important;background:#005c35!important;}
        .home-page{display:block!important;width:100%!important;height:auto!important;min-height:0!important;margin:0!important;padding:0!important;flex:none!important;overflow:visible!important;background:#f1f6fb!important;}
        .home-footer{display:block!important;margin:0!important;padding:5px 7px!important;min-height:0!important;line-height:1.15!important;}
        .home-footer small{margin-top:2px!important;}
        .home-notice-panel .home-panel-head{min-height:30px!important;padding:4px 7px!important;gap:5px!important;}
        .home-notice-panel .home-panel-head h2{font-size:12px!important;line-height:1.15!important;}
        .home-notice-panel .home-panel-head a{font-size:9px!important;padding:3px 6px!important;}
        .home-about #contact{display:block!important;min-width:0!important;}
        .home-about #contact p:nth-of-type(1),
        .home-about #contact p:nth-of-type(2){display:block!important;width:100%!important;margin:3px 0!important;font-size:11px!important;line-height:1.25!important;overflow-wrap:anywhere!important;}
        .home-about #contact p:nth-of-type(3){margin:3px 0 0!important;font-size:10px!important;line-height:1.25!important;}
      }

      /* V93: desktop login buttons — keep SVG icons from expanding the anchor height. */
      @media(min-width:721px){
        .home-page .home-login-card>a{min-height:58px!important;height:58px!important;display:flex!important;align-items:center!important;gap:12px!important;box-sizing:border-box!important;}
        .home-page .home-login-icon{display:block!important;width:30px!important;height:30px!important;flex:0 0 30px!important;fill:none!important;stroke:currentColor!important;stroke-width:1.8!important;stroke-linecap:round!important;stroke-linejoin:round!important;}
        .home-page .home-login-label{display:block!important;flex:1 1 auto!important;text-align:left!important;line-height:1.2!important;}
        .home-page .home-login-arrow{display:block!important;flex:0 0 auto!important;font-size:28px!important;line-height:1!important;margin-left:auto!important;}
      }
    
      @media(max-width:720px){
        .home-page .home-nav{display:flex!important;flex-direction:column!important;align-items:stretch!important;justify-content:center!important;gap:5px!important;min-height:0!important;padding:7px 9px!important}
        .home-page .home-brand{display:flex!important;align-items:center!important;min-height:var(--front-header-height,76px)!important;gap:8px!important}
        .home-page .home-brand img{width:var(--front-logo-size,72px)!important;height:var(--front-logo-size,72px)!important;max-width:24vw!important;flex:0 0 auto!important}
        .home-page .home-links{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;width:100%!important;gap:2px!important;justify-content:stretch!important;border-top:1px solid rgba(7,92,55,.16)!important;padding-top:4px!important}
        .home-page .home-links a,.home-page .home-links a:nth-child(n+3){display:flex!important;align-items:center!important;justify-content:center!important;min-width:0!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;font-size:clamp(8px,var(--front-nav-font-size,12px),12px)!important;line-height:1.15!important;padding:var(--front-nav-item-padding,7px) 1px!important;border-radius:5px!important}
      }
      </style>
      <style>
      /* V94: restore the moving notice ticker on the public front page. */
      .home-page .home-notices{overflow:hidden!important;position:relative;}
      .home-page .home-notice-track{transition:transform .65s ease!important;will-change:transform;}
      @media(min-width:721px){.home-page .home-notices{height:66px!important;padding-top:0!important;padding-bottom:0!important}.home-page .home-notice{min-height:66px!important;padding:12px 0!important}}
      @media(max-width:720px){.home-page .home-notices{overflow:hidden!important;max-height:none!important}.home-page .home-notice-track{animation:none!important}}
      </style>

      <script>
      function scrollHomeMembers(direction){var track=document.getElementById('homeMembersTrack');if(!track)return;track.style.setProperty('overflow-x','auto','important');var card=track.querySelector('.home-member');var gap=parseFloat(getComputedStyle(track).gap)||6;var amount=card?card.getBoundingClientRect().width+gap:220;if(track.scrollBy)track.scrollBy({left:direction*amount,behavior:'smooth'});else track.scrollLeft+=direction*amount;}
      document.addEventListener('DOMContentLoaded',function(){
        var track=document.getElementById('homeMembersTrack');if(!track)return;
        var slider=track.closest('.home-member-slider');var cards=track.querySelectorAll('.home-member');if(cards.length<2)return;
        var timer=null;var hoverOK=window.matchMedia('(hover:hover)').matches;
        function next(){if(document.hidden||slider.contains(document.activeElement)||(hoverOK&&slider.matches(':hover')))return;
          var card=cards[0];var gap=parseFloat(getComputedStyle(track).gap)||10;var step=card.getBoundingClientRect().width+gap;
          var max=track.scrollWidth-track.clientWidth;if(max<=2)return;
          if(track.scrollLeft+step>=max-4)track.scrollTo({left:0,behavior:'smooth'});else track.scrollBy({left:step,behavior:'smooth'});
        }
        function start(){if(!timer&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches)timer=setInterval(next,3500);}
        function stop(){if(timer){clearInterval(timer);timer=null;}}
        if(hoverOK){slider.addEventListener('mouseenter',stop);slider.addEventListener('mouseleave',start);}
        slider.addEventListener('focusin',stop);slider.addEventListener('focusout',start);
        document.addEventListener('visibilitychange',function(){document.hidden?stop():start();});start();
      });
      // Continuous marquee for every visible notice; repeat short feeds to fill the viewport.
      document.addEventListener('DOMContentLoaded',function(){
        var panel=document.querySelector('.home-page .home-notice-panel');if(!panel)return;
        var viewport=panel.querySelector('.home-notices'),track=panel.querySelector('.home-notice-track');
        if(!viewport||!track||track.dataset.marqueeReady==='1')return;
        var source=Array.prototype.slice.call(track.querySelectorAll(':scope > .home-notice')).map(function(item){return item.cloneNode(true);});
        if(!source.length)return;
        track.dataset.marqueeReady='1';
        function copy(item){var el=item.cloneNode(true);el.setAttribute('aria-hidden','true');el.classList.add('home-notice-copy');return el;}
        var width=Math.max(viewport.clientWidth||window.innerWidth||360,360),copies=0;
        while(track.scrollWidth<width*1.25&&copies<20){source.forEach(function(item){track.appendChild(copy(item));});copies++;}
        var base=Array.prototype.slice.call(track.children);
        base.forEach(function(item){track.appendChild(copy(item));});
        viewport.style.setProperty('overflow','hidden','important');viewport.style.setProperty('white-space','nowrap','important');
        track.style.setProperty('display','flex','important');track.style.setProperty('width','max-content','important');track.style.setProperty('max-width','none','important');
        track.style.setProperty('animation','gsHomeNoticeMarquee 24s linear infinite','important');
        /* Keep the notice marquee running; do not freeze it on pointer hover. */
        track.style.setProperty('animation-play-state','running','important');
        window.addEventListener('resize',function(){track.style.setProperty('animation-duration','24s','important');});
      });
      </script>
    <style>
      /* V116: reference-photo hero composition — keep people visible on the left and place copy in the open right area. */
      @media(min-width:1051px){
        .home-page .home-hero{position:relative;display:block;min-height:365px;padding:0 38px;overflow:hidden;background-position:left center;}
        .home-page .home-hero-copy{position:absolute;left:52%;top:42px;width:min(300px,calc(100% - 430px));padding:0!important;z-index:1;}
        .home-page .home-hero-copy h1{max-width:none;font-size:clamp(30px,2.8vw,40px);}
        .home-page .home-hero-copy p{width:100%;font-size:clamp(16px,1.55vw,22px);}
        .home-page .home-hero-copy .home-swoosh{width:240px;margin-left:30px;}
        .home-page .home-login-card{position:absolute;right:38px;top:14px;width:clamp(280px,22vw,360px);z-index:2;}
        .home-page .home-hero-copy h1,.home-page .home-hero-copy p{ text-shadow:0 1px 2px rgba(255,255,255,.55);}
      }
      @media(min-width:721px) and (max-width:1050px){
        .home-page .home-hero-copy{padding-left:35%!important;}
      }
      /* V170: four visible members, rotating list, and moving notices on desktop/mobile. */
      .home-page .home-member-slider{overflow:hidden!important;padding-left:30px!important;padding-right:30px!important;}
      .home-page .home-members{display:flex!important;flex-flow:row nowrap!important;gap:10px!important;width:100%!important;overflow-x:auto!important;scroll-snap-type:x mandatory!important;scroll-behavior:smooth!important;}
      .home-page .home-member{flex:0 0 calc((100% - 30px)/4)!important;min-width:0!important;scroll-snap-align:start!important;}
      .home-page .home-notices{display:block!important;height:66px!important;min-height:66px!important;max-height:66px!important;padding:0!important;overflow:hidden!important;white-space:nowrap!important;}
      .home-page .home-notice-track{display:flex!important;flex-flow:row nowrap!important;align-items:stretch!important;width:max-content!important;max-width:none!important;animation:gsHomeNoticeMarquee 34s linear infinite!important;transition:none!important;will-change:transform!important;}
      .home-page .home-notice{display:flex!important;flex:0 0 clamp(360px,50vw,760px)!important;width:clamp(360px,50vw,760px)!important;min-width:clamp(360px,50vw,760px)!important;height:66px!important;min-height:66px!important;align-items:center!important;overflow:hidden!important;white-space:nowrap!important;padding:7px 14px!important;}
      .home-page .home-notice>div{display:flex!important;align-items:center!important;gap:8px!important;min-width:0!important;white-space:nowrap!important;}
      .home-page .home-notice b,.home-page .home-notice p{white-space:nowrap!important;display:inline-block!important;overflow:hidden!important;text-overflow:ellipsis!important;max-width:48vw!important;}
      .home-page .home-notice p{margin:0!important;}
      .home-page .home-notice time{display:none!important;}
      .home-page .home-notice-track:hover{animation-play-state:paused!important;}
      @media(max-width:720px){
        .home-page .home-member{flex:0 0 calc(50% - 5px)!important;}
        .home-page .home-member-photo{height:90px!important;}
        .home-page .home-notice{flex-basis:100vw!important;width:100vw!important;min-width:100vw!important;max-width:100vw!important;}
        .home-page .home-notice b,.home-page .home-notice p{max-width:72vw!important;}
        .home-page .home-notice-track{animation-duration:42s!important;}
      }
      /* V173: stop database-backed notice text/cards from widening the mobile home page. */
      @media(max-width:720px){
        html:has(.home-page),body:has(.home-page){width:100%!important;max-width:100%!important;min-width:0!important;overflow-x:hidden!important;}
        .home-page{display:block!important;width:100%!important;max-width:100vw!important;min-width:0!important;height:auto!important;min-height:0!important;overflow-x:hidden!important;}
        .home-page .home-section-grid,.home-page .home-panel-grid{display:grid!important;grid-template-columns:minmax(0,1fr)!important;width:100%!important;max-width:100%!important;min-width:0!important;}
        .home-page .home-panel,.home-page .home-notice-panel{width:100%!important;max-width:100%!important;min-width:0!important;box-sizing:border-box!important;}
        .home-page .home-notices{display:block!important;width:100%!important;max-width:100%!important;min-width:0!important;height:58px!important;min-height:58px!important;max-height:58px!important;overflow:hidden!important;box-sizing:border-box!important;}
        .home-page .home-notice-track{display:flex!important;flex-flow:row nowrap!important;align-items:stretch!important;width:max-content!important;max-width:none!important;height:58px!important;min-height:58px!important;animation:gsHomeNoticeMarquee 38s linear infinite!important;}
        .home-page .home-notice{display:flex!important;flex:0 0 100vw!important;width:100vw!important;min-width:100vw!important;max-width:100vw!important;height:58px!important;min-height:58px!important;max-height:58px!important;padding:5px 10px!important;gap:7px!important;box-sizing:border-box!important;overflow:hidden!important;}
        .home-page .home-notice>div{display:flex!important;flex:1 1 auto!important;min-width:0!important;max-width:calc(100vw - 52px)!important;overflow:hidden!important;gap:6px!important;}
        .home-page .home-notice b,.home-page .home-notice p{display:inline-block!important;flex:0 1 auto!important;min-width:0!important;max-width:calc(100vw - 88px)!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;font-size:11px!important;line-height:1.2!important;}
        .home-page .home-member-slider,.home-page .home-members{max-width:100%!important;min-width:0!important;}
      }
      /* V174: Android may report a wide CSS viewport; force the compact public-home layout up to tablet/desktop-site widths. */
      @media(max-width:1200px){
        html:has(.home-page),body:has(.home-page){width:100%!important;max-width:100%!important;min-width:0!important;overflow-x:hidden!important;}
        .home-page{display:block!important;width:100%!important;max-width:100vw!important;min-width:0!important;height:auto!important;min-height:0!important;overflow-x:hidden!important;}
        .home-page .home-top{display:none!important;}
        .home-page .home-nav{display:flex!important;flex-wrap:wrap!important;gap:5px!important;padding:7px 10px!important;min-width:0!important;}
        .home-page .home-brand{flex:1 1 auto!important;min-width:0!important;max-width:100%!important;}
        .home-page .home-brand img{width:42px!important;height:42px!important;flex:0 0 42px!important;}
        .home-page .home-brand b{font-size:clamp(13px,3vw,17px)!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;}
        .home-page .home-brand small{font-size:10px!important;}
        .home-page .home-links{display:flex!important;flex:1 1 100%!important;width:100%!important;max-width:100%!important;min-width:0!important;overflow-x:auto!important;justify-content:flex-start!important;gap:5px!important;padding:2px 0!important;white-space:nowrap!important;}
        .home-page .home-links a{flex:0 0 auto!important;padding:6px 9px!important;font-size:11px!important;white-space:nowrap!important;}
        .home-page .home-hero{position:relative!important;display:flex!important;flex-direction:column!important;align-items:stretch!important;justify-content:flex-start!important;gap:8px!important;width:100%!important;min-width:0!important;min-height:0!important;height:auto!important;padding:14px 12px!important;overflow:hidden!important;background-position:center!important;background-size:cover!important;}
        .home-page .home-hero-copy{position:relative!important;inset:auto!important;left:auto!important;right:auto!important;top:auto!important;bottom:auto!important;display:flex!important;flex-direction:column!important;align-items:center!important;width:100%!important;max-width:100%!important;min-width:0!important;padding:4px 6px!important;text-align:center!important;}
        .home-page .home-hero-copy h1{width:100%!important;max-width:100%!important;margin:0 0 5px!important;font-size:clamp(21px,5vw,30px)!important;line-height:1.12!important;text-align:center!important;overflow-wrap:anywhere!important;}
        .home-page .home-hero-copy p{width:auto!important;max-width:100%!important;margin:0!important;padding:6px 10px!important;font-size:clamp(12px,3vw,16px)!important;line-height:1.3!important;text-align:center!important;}
        .home-page .home-hero-copy .home-swoosh{width:min(180px,55vw)!important;margin:5px auto!important;}
        .home-page .home-login-card{position:relative!important;inset:auto!important;right:auto!important;top:auto!important;width:100%!important;max-width:430px!important;min-width:0!important;margin:0 auto!important;padding:10px 12px!important;}
        .home-page .home-login-card h2{font-size:14px!important;margin:0 0 6px!important;}
        .home-page .home-login-card>a{height:40px!important;min-height:40px!important;margin:4px 0!important;padding:7px 10px!important;font-size:13px!important;}
        .home-page .home-login-card h3{font-size:12px!important;margin:6px 0 3px!important;}
        .home-page .home-login-card ul{margin:3px 0 0!important;padding-left:18px!important;}
        .home-page .home-login-card li{font-size:10px!important;line-height:1.35!important;margin:2px 0!important;}
        .home-page .home-section-grid{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:8px!important;width:100%!important;max-width:100%!important;min-width:0!important;margin:6px 0!important;padding:0 8px!important;}
        .home-page .home-panel,.home-page .home-notice-panel{width:100%!important;max-width:100%!important;min-width:0!important;margin:0!important;box-sizing:border-box!important;}
        .home-page .home-panel-head{min-height:38px!important;padding:6px 9px!important;}
        .home-page .home-panel-head h2{font-size:13px!important;}
        .home-page .home-member-slider{width:100%!important;max-width:100%!important;min-width:0!important;overflow:hidden!important;padding:0 24px!important;}
        .home-page .home-members{display:flex!important;flex-flow:row nowrap!important;gap:8px!important;width:100%!important;max-width:100%!important;min-width:0!important;overflow-x:auto!important;padding:7px 2px!important;}
        .home-page .home-member{flex:0 0 calc(50% - 4px)!important;width:calc(50% - 4px)!important;min-width:0!important;max-width:calc(50% - 4px)!important;}
        .home-page .home-member-photo{height:76px!important;}
        .home-page .home-member b{font-size:11px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;}
        .home-page .home-member small{font-size:9px!important;}
        .home-page .home-notices{display:block!important;position:relative!important;width:100%!important;max-width:100%!important;min-width:0!important;height:52px!important;min-height:52px!important;max-height:52px!important;overflow:hidden!important;white-space:nowrap!important;box-sizing:border-box!important;}
        .home-page .home-notice-track{display:flex!important;flex-flow:row nowrap!important;align-items:stretch!important;width:max-content!important;max-width:none!important;height:52px!important;min-height:52px!important;animation:gsHomeNoticeMarquee 34s linear infinite!important;transition:none!important;}
        .home-page .home-notice{display:flex!important;flex:0 0 100vw!important;width:100vw!important;min-width:100vw!important;max-width:100vw!important;height:52px!important;min-height:52px!important;max-height:52px!important;align-items:center!important;padding:4px 9px!important;gap:6px!important;overflow:hidden!important;box-sizing:border-box!important;white-space:nowrap!important;}
        .home-page .home-notice>div{display:flex!important;flex:1 1 auto!important;min-width:0!important;max-width:calc(100vw - 54px)!important;overflow:hidden!important;gap:5px!important;}
        .home-page .home-notice b,.home-page .home-notice p{display:inline-block!important;flex:0 1 auto!important;min-width:0!important;max-width:calc(100vw - 84px)!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;font-size:11px!important;line-height:1.2!important;}
        .home-page .home-notice time{display:none!important;}
        .home-page .home-latest-contribution{display:flex!important;align-items:center!important;flex-flow:row nowrap!important;gap:7px!important;width:auto!important;max-width:calc(100% - 16px)!important;min-width:0!important;min-height:40px!important;margin:0 8px 10px!important;padding:6px 8px!important;overflow:hidden!important;box-sizing:border-box!important;}
        .home-page .home-latest-contribution-title{flex:0 0 auto!important;max-width:30%!important;font-size:10px!important;line-height:1.2!important;white-space:nowrap!important;}
        .home-page .home-latest-contribution-viewport{display:block!important;flex:1 1 auto!important;width:0!important;min-width:0!important;max-width:100%!important;height:24px!important;overflow:hidden!important;white-space:nowrap!important;}
        .home-page .home-latest-contribution-track{display:flex!important;flex-flow:row nowrap!important;align-items:center!important;width:max-content!important;max-width:none!important;height:24px!important;animation:gsContributionTicker 30s linear infinite!important;}
        .home-page .home-latest-contribution-item{display:block!important;flex:0 0 auto!important;max-width:none!important;padding:0 24px 0 8px!important;font-size:10px!important;line-height:1.2!important;white-space:nowrap!important;}
        .home-page .home-about{display:block!important;width:auto!important;max-width:calc(100% - 16px)!important;margin:0 8px 8px!important;padding:10px!important;}
        .home-page .home-about #contact{border:0!important;border-top:1px solid #d6e8da!important;padding:8px 0 0!important;margin-top:8px!important;}
        .home-page .home-contribution{display:flex!important;flex-direction:column!important;align-items:flex-start!important;gap:8px!important;width:auto!important;max-width:calc(100% - 16px)!important;margin:0 8px 8px!important;padding:10px!important;}
        .home-page .home-features{grid-template-columns:repeat(2,minmax(0,1fr))!important;width:auto!important;max-width:calc(100% - 16px)!important;margin:0 8px 8px!important;}
        .home-page .home-footer{padding:10px!important;}
      }
      /* V175: notices use the same compact ribbon treatment as Latest Contribution. */
      .home-page .home-notice-panel{background:transparent!important;border:0!important;box-shadow:none!important;padding:0!important;min-width:0!important;}
      .home-page .home-notice-ticker{display:flex!important;align-items:center!important;flex-flow:row nowrap!important;gap:10px!important;width:auto!important;max-width:100%!important;min-width:0!important;min-height:48px!important;margin:0!important;padding:8px 12px!important;overflow:hidden!important;box-sizing:border-box!important;}
      .home-page .home-notice-ticker-title{flex:0 0 auto!important;max-width:38%!important;color:#14532d!important;font-size:clamp(11px,1.1vw,14px)!important;font-weight:800!important;line-height:1.2!important;white-space:normal!important;}
      .home-page .home-notice-ticker-viewport{display:block!important;flex:1 1 0!important;width:0!important;min-width:0!important;max-width:100%!important;overflow:hidden!important;white-space:nowrap!important;}
      .home-page .home-notice-ticker-track{display:flex!important;flex-flow:row nowrap!important;align-items:center!important;width:max-content!important;max-width:none!important;will-change:transform!important;}
      .home-page .home-notice-ticker-item{display:inline-flex!important;align-items:center!important;flex:0 0 auto!important;gap:6px!important;padding:0 32px 0 8px!important;color:#345344!important;font-size:12px!important;font-weight:650!important;line-height:1.25!important;white-space:nowrap!important;}
      .home-page .home-notice-ticker-item b{color:#075d35!important;font-weight:800!important;}
      .home-page .home-notice-ticker-item small{color:#718276!important;font-size:10px!important;}
      @media(max-width:1200px){
        .home-page .home-notice-ticker{width:auto!important;max-width:calc(100% - 16px)!important;min-height:46px!important;margin:0 8px 8px!important;padding:6px 8px!important;gap:7px!important;}
        .home-page .home-notice-ticker-title{max-width:42%!important;font-size:clamp(10px,1.45vw,12px)!important;}
        .home-page .home-notice-ticker-item{gap:5px!important;padding:0 22px 0 7px!important;font-size:11px!important;}
        .home-page .home-notice-ticker-item small{font-size:9px!important;}
      }
      @media(min-width:1201px){
        .home-page .home-hero.home-hero-copy-right{position:relative!important;display:flex!important;flex-direction:column!important;align-items:flex-end!important;justify-content:center!important;gap:12px!important;min-height:450px!important;padding:30px clamp(36px,8vw,120px) 30px 35px!important;}
        .home-page .home-hero.home-hero-copy-right .home-hero-copy{position:relative!important;inset:auto!important;width:min(440px,48%)!important;max-width:48%!important;margin:0!important;padding:0!important;display:flex!important;flex-direction:column!important;align-items:flex-end!important;text-align:right!important;z-index:1!important;}
        .home-page .home-hero.home-hero-copy-right .home-hero-copy h1,.home-page .home-hero.home-hero-copy-right .home-hero-copy p{width:100%!important;text-align:right!important;}
        .home-page .home-hero.home-hero-copy-right .home-login-card{position:relative!important;inset:auto!important;right:auto!important;top:auto!important;width:min(440px,48%)!important;max-width:48%!important;margin:0!important;align-self:flex-end!important;z-index:1!important;}
        .home-page .home-hero.home-hero-copy-left{position:relative!important;display:flex!important;flex-direction:column!important;align-items:flex-start!important;justify-content:center!important;gap:12px!important;min-height:450px!important;padding:30px 35px 30px clamp(36px,8vw,120px)!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy{position:relative!important;inset:auto!important;width:min(440px,48%)!important;max-width:48%!important;margin:0!important;padding:0!important;display:flex!important;flex-direction:column!important;align-items:flex-start!important;text-align:left!important;z-index:1!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy h1,.home-page .home-hero.home-hero-copy-left .home-hero-copy p{text-align:left!important;}
        .home-page .home-hero.home-hero-copy-left .home-login-card{position:relative!important;inset:auto!important;right:auto!important;top:auto!important;width:min(440px,48%)!important;max-width:48%!important;margin:0!important;align-self:flex-start!important;z-index:1!important;}
      }
      @media(max-width:1200px){
        .home-page .home-hero.home-hero-copy-right .home-hero-copy{align-items:flex-end!important;text-align:right!important;}
        .home-page .home-hero.home-hero-copy-right .home-hero-copy h1,.home-page .home-hero.home-hero-copy-right .home-hero-copy p{text-align:right!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy{align-items:flex-start!important;text-align:left!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy h1,.home-page .home-hero.home-hero-copy-left .home-hero-copy p{text-align:left!important;}
      }
      .home-page .home-nav{background-color:var(--front-header-bg,#fff)!important;background-image:var(--front-header-artwork,none)!important;background-size:var(--front-header-fit,contain)!important;background-position:center!important;background-repeat:no-repeat!important;color:var(--front-header-text,#075c37)!important;}
      .home-page .home-nav .home-brand{color:var(--front-header-text,#075c37)!important;}
      .home-page .home-nav .home-brand b,.home-page .home-nav .home-brand small{color:inherit!important;}
      .home-page .home-nav .home-links a{color:var(--front-header-text,#075c37)!important;}
      .home-page .home-nav .home-links a.home-active,.home-page .home-nav .home-links a:hover{background:var(--front-header-accent,#08783e)!important;color:#fff!important;}
      .home-page .home-hero{background-position:var(--front-banner-position,center)!important;}
      .home-page .home-hero .home-hero-copy h1{color:<?= $bannerOverlay==='green'?'#ffffff':($bannerOverlay==='blue'?'#ffffff':'#006132') ?>!important;}
      @keyframes gsHomeNoticeTickerMove{from{transform:translateX(0)}to{transform:translateX(-50%)}}
      /* Final responsive header sizing: brand first, then all four menu links in one thin row. */
      @media(max-width:1200px){
        .home-page .home-nav{display:flex!important;flex-direction:column!important;flex-wrap:nowrap!important;align-items:stretch!important;justify-content:center!important;gap:5px!important;min-height:0!important;padding:7px 9px!important;}
        .home-page .home-brand{display:flex!important;flex:0 0 auto!important;align-items:center!important;min-width:0!important;min-height:var(--front-header-height,76px)!important;max-width:100%!important;gap:8px!important;}
        .home-page .home-brand img{width:var(--front-logo-size,72px)!important;height:var(--front-logo-size,72px)!important;max-width:24vw!important;flex:0 0 auto!important;}
        .home-page .home-brand b{font-size:clamp(12px,var(--front-brand-name-size,28px),48px)!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;}
        .home-page .home-brand small{font-size:clamp(8px,var(--front-brand-tagline-size,17px),24px)!important;}
        .home-page .home-links{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;flex:0 0 auto!important;width:100%!important;max-width:100%!important;min-width:0!important;overflow:visible!important;gap:2px!important;justify-content:stretch!important;border-top:1px solid rgba(7,92,55,.16)!important;padding:4px 0 0!important;white-space:normal!important;}
        .home-page .home-links a,.home-page .home-links a:nth-child(n+3){display:flex!important;flex:1 1 0!important;align-items:center!important;justify-content:center!important;min-width:0!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;font-size:clamp(8px,var(--front-nav-font-size,12px),12px)!important;line-height:1.15!important;padding:var(--front-nav-item-padding,7px) 1px!important;border-radius:5px!important;}
      }
      /* V180: final auto-fit rules override earlier fixed 450px hero and oversized mobile branding. */
      @media(min-width:1201px){
        .home-page{width:100%;max-width:100vw;overflow-x:hidden;}
        .home-page .home-top{padding:5px clamp(14px,2vw,24px)!important;font-size:11px!important;gap:9px!important;}
        .home-page .home-top-left,.home-page .home-top-right{gap:10px!important;}
        .home-page .home-top-right strong{font-size:12px!important;}
        .home-page .home-nav{min-height:60px!important;height:auto!important;padding:4px clamp(14px,2vw,24px)!important;gap:12px!important;}
        .home-page .home-brand{min-width:0!important;min-height:48px!important;gap:8px!important;}
        .home-page .home-brand img{width:min(var(--front-logo-size,72px),48px)!important;height:min(var(--front-logo-size,72px),48px)!important;}
        .home-page .home-brand b{font-size:min(var(--front-brand-name-size,28px),22px)!important;line-height:1.1!important;}
        .home-page .home-brand small{font-size:min(var(--front-brand-tagline-size,17px),12px)!important;line-height:1.15!important;}
        .home-page .home-links{gap:4px!important;}
        .home-page .home-links a{padding:6px 8px!important;font-size:min(var(--front-nav-font-size,12px),12px)!important;}
        .home-page .home-links a:not(.home-active){background:rgba(255,255,255,.82)!important;color:#075c37!important;box-shadow:0 1px 4px rgba(4,48,27,.12)!important;}
        .home-page .home-brand>span{padding:3px 6px!important;border-radius:7px!important;background:rgba(255,255,255,.62)!important;}
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{
          display:grid!important;grid-template-columns:minmax(0,1fr) minmax(250px,330px)!important;grid-template-rows:auto!important;
          flex-direction:unset!important;align-items:center!important;justify-content:stretch!important;gap:clamp(12px,2vw,22px)!important;
          width:100%!important;min-width:0!important;min-height:clamp(265px,28vw,350px)!important;height:auto!important;
          padding:clamp(16px,2.5vw,28px) clamp(18px,3.5vw,48px)!important;overflow:hidden!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy,.home-page .home-hero.home-hero-copy-left .home-hero-copy{
          position:relative!important;inset:auto!important;width:100%!important;max-width:100%!important;min-width:0!important;margin:0!important;padding:0!important;z-index:1!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy{grid-column:2!important;grid-row:1!important;}
        .home-page .home-hero.home-hero-copy-right .home-login-card{grid-column:1!important;grid-row:1!important;justify-self:start!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy{grid-column:1!important;grid-row:1!important;}
        .home-page .home-hero.home-hero-copy-left .home-login-card{grid-column:2!important;grid-row:1!important;justify-self:end!important;}
        .home-page .home-hero .home-hero-copy h1{font-size:clamp(24px,2.5vw,35px)!important;line-height:1.1!important;margin:0 0 8px!important;overflow-wrap:anywhere!important;}
        .home-page .home-hero .home-hero-copy p{width:auto!important;max-width:100%!important;padding:8px 13px!important;font-size:clamp(15px,1.4vw,19px)!important;line-height:1.3!important;}
        .home-page .home-hero .home-login-card{position:relative!important;inset:auto!important;width:min(100%,330px)!important;max-width:330px!important;min-width:0!important;margin:0!important;padding:11px!important;z-index:1!important;}
        .home-page .home-login-card h2{font-size:15px!important;margin:0 0 7px!important;}
        .home-page .home-login-card a{padding:8px 10px!important;margin:6px 0!important;font-size:13px!important;}
        .home-page .home-login-card h3{font-size:12px!important;margin:8px 0 4px!important;padding:6px!important;}
        .home-page .home-login-card li{font-size:10px!important;padding:2px 0!important;}
        .home-page .home-section-grid{grid-template-columns:minmax(0,1.1fr) minmax(0,.95fr)!important;gap:12px!important;padding:12px clamp(14px,2vw,24px)!important;min-width:0!important;}
        .home-page .home-section-grid>*{min-width:0!important;}
        .home-page .home-panel-head{padding:8px 11px!important;}
        .home-page .home-panel-head h2{font-size:16px!important;}
        .home-page .home-member-photo{height:100px!important;}
        .home-page .home-member b{font-size:12px!important;padding:5px 3px 0!important;}
        .home-page .home-member small{font-size:10px!important;}
        .home-page .home-about,.home-page .home-contribution{padding:13px 16px!important;margin-left:clamp(14px,2vw,24px)!important;margin-right:clamp(14px,2vw,24px)!important;}
        .home-page .home-features{margin-left:clamp(14px,2vw,24px)!important;margin-right:clamp(14px,2vw,24px)!important;padding:9px 12px!important;}
        .home-page .home-footer{padding:11px clamp(14px,2vw,24px)!important;}
      }
      @media(max-width:650px){
        .home-page{width:100%!important;max-width:100vw!important;overflow-x:hidden!important;}
        .home-page .home-top{padding:4px 8px!important;font-size:9px!important;gap:5px!important;}
        .home-page .home-top-left{gap:6px!important;}
        .home-page .home-top-right{display:none!important;}
        .home-page .home-nav{padding:5px 7px!important;gap:3px!important;}
        .home-page .home-brand{min-height:42px!important;gap:6px!important;}
        .home-page .home-brand img{width:min(var(--front-logo-size,72px),36px)!important;height:min(var(--front-logo-size,72px),36px)!important;max-width:15vw!important;}
        .home-page .home-brand b{font-size:clamp(12px,3.7vw,15px)!important;line-height:1.1!important;}
        .home-page .home-brand small{font-size:clamp(8px,2.7vw,10px)!important;line-height:1.1!important;margin-top:1px!important;}
        .home-page .home-links a{font-size:clamp(8px,2.6vw,10px)!important;padding:5px 1px!important;}
        .home-page .home-links a:not(.home-active){background:rgba(255,255,255,.86)!important;color:#075c37!important;box-shadow:0 1px 3px rgba(4,48,27,.10)!important;}
        .home-page .home-brand>span{padding:2px 4px!important;border-radius:6px!important;background:rgba(255,255,255,.66)!important;}
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{min-height:0!important;height:auto!important;padding:10px 9px!important;gap:8px!important;}
        .home-page .home-hero .home-login-card{width:100%!important;max-width:100%!important;padding:10px!important;}
        .home-page .home-section-grid{padding:8px!important;gap:8px!important;}
        .home-page .home-about,.home-page .home-contribution{padding:9px!important;margin:0 8px 8px!important;}
      }
      /* V182: artwork-only hides only the duplicate brand lockup; nav remains visible. */
      .home-page .home-nav{position:relative!important;isolation:isolate!important;overflow:hidden!important;background-image:none!important;}
      .home-page .home-nav .home-nav-artwork{position:absolute!important;inset:0!important;display:block!important;width:100%!important;height:100%!important;max-width:none!important;object-fit:var(--front-header-fit,cover)!important;object-position:center!important;opacity:1!important;filter:none!important;z-index:0!important;margin:0!important;padding:0!important;pointer-events:none!important;}
      .home-page .home-nav .home-brand,.home-page .home-nav .home-links{position:relative!important;z-index:1!important;}
      .home-page .home-nav[style*="--front-artwork-only:1"]{display:flex!important;min-height:60px!important;height:auto!important;}
      .home-page .home-nav[style*="--front-artwork-only:1"] .home-brand-hidden-for-artwork{display:none!important;}
      .home-page .home-nav[style*="--front-artwork-only:1"] .home-links{display:flex!important;visibility:visible!important;opacity:1!important;}
      @media(max-width:650px){
        .home-page .home-nav[style*="--front-artwork-only:1"]{min-height:48px!important;padding:6px 8px!important;}
        .home-page .home-nav[style*="--front-artwork-only:1"] .home-links{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;width:100%!important;border-top:0!important;padding-top:0!important;}
      }
      /* Keep the desktop hero in a fixed two-column grid; content-side changes never push login below. */
      @media(min-width:1201px){
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{
          display:grid!important;grid-template-columns:minmax(0,1fr) minmax(320px,380px)!important;grid-template-rows:minmax(0,1fr)!important;
          align-items:center!important;min-height:clamp(340px,32vw,410px)!important;height:auto!important;gap:clamp(18px,3vw,40px)!important;
          padding:clamp(20px,3vw,40px) clamp(24px,4vw,64px)!important;overflow:hidden!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy,.home-page .home-hero.home-hero-copy-left .home-hero-copy{
          grid-row:1!important;align-self:center!important;justify-self:stretch!important;min-width:0!important;width:100%!important;max-width:none!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy{grid-column:2!important;}
        .home-page .home-hero.home-hero-copy-right .home-login-card{grid-column:1!important;justify-self:start!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy{grid-column:1!important;}
        .home-page .home-hero.home-hero-copy-left .home-login-card{grid-column:2!important;justify-self:end!important;}
        .home-page .home-hero .home-login-card{grid-row:1!important;align-self:center!important;position:relative!important;inset:auto!important;width:100%!important;max-width:380px!important;min-width:320px!important;min-height:0!important;padding:18px!important;box-sizing:border-box!important;}
        .home-page .home-login-card h2{font-size:18px!important;margin:0 0 10px!important;line-height:1.25!important;}
        .home-page .home-login-card a{min-height:42px!important;padding:10px 13px!important;margin:8px 0!important;font-size:15px!important;}
        .home-page .home-login-card h3{font-size:14px!important;margin:12px 0 6px!important;padding:8px!important;}
        .home-page .home-login-card li{font-size:12px!important;padding:3px 0!important;line-height:1.35!important;}
        .home-page .home-hero .home-hero-copy h1{font-size:clamp(26px,2.5vw,38px)!important;}
        .home-page .home-hero .home-hero-copy p{font-size:clamp(16px,1.5vw,21px)!important;}
      }
      /* V185: glass/transparent login actions with compact mobile dimensions. */
      .home-page .home-login-card>a.home-login-member,.home-page .home-login-card>a.home-login-admin{
        display:flex!important;align-items:center!important;justify-content:flex-start!important;gap:10px!important;width:100%!important;max-width:100%!important;min-width:0!important;min-height:44px!important;height:auto!important;
        margin:7px 0!important;padding:10px 13px!important;box-sizing:border-box!important;overflow:hidden!important;border:1.5px solid rgba(7,92,55,.56)!important;border-radius:10px!important;
        background:rgba(255,255,255,.24)!important;color:#075c37!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.42),0 2px 6px rgba(0,55,32,.08)!important;
        font-size:14px!important;font-weight:800!important;line-height:1.2!important;text-decoration:none!important;backdrop-filter:blur(3px)!important;
      }
      .home-page .home-login-card>a.home-login-member:hover,.home-page .home-login-card>a.home-login-admin:hover{background:rgba(255,255,255,.44)!important;border-color:rgba(7,92,55,.82)!important;}
      .home-page .home-login-card .home-login-icon{display:block!important;width:19px!important;height:19px!important;min-width:19px!important;flex:0 0 19px!important;stroke:currentColor!important;}
      .home-page .home-login-card .home-login-label{display:block!important;min-width:0!important;flex:1 1 auto!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;}
      .home-page .home-login-card .home-login-arrow{display:block!important;flex:0 0 auto!important;margin-left:auto!important;font-size:20px!important;line-height:1!important;}
      @media(max-width:650px){
        .home-page .home-login-card>a.home-login-member,.home-page .home-login-card>a.home-login-admin{width:min(100%,260px)!important;max-width:260px!important;min-width:0!important;min-height:35px!important;height:35px!important;margin:4px auto!important;padding:6px 10px!important;gap:7px!important;font-size:12px!important;justify-content:center!important;}
        .home-page .home-login-card .home-login-icon{width:16px!important;height:16px!important;min-width:16px!important;flex-basis:16px!important;}
        .home-page .home-login-card .home-login-label{flex:0 1 auto!important;max-width:calc(100% - 48px)!important;}
        .home-page .home-login-card .home-login-arrow{font-size:17px!important;}
      }
      /* V186: hero copy and login card sit in opposite diagonal corners on desktop. */
      @media(min-width:651px){
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{
          display:grid!important;grid-template-columns:minmax(0,1fr) minmax(260px,min(38vw,380px))!important;grid-template-rows:minmax(0,1fr)!important;
          align-items:stretch!important;min-height:clamp(360px,35vw,460px)!important;height:auto!important;gap:clamp(12px,2vw,28px)!important;
          padding:clamp(18px,3vw,40px)!important;overflow:hidden!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy,.home-page .home-hero.home-hero-copy-left .home-hero-copy{
          grid-row:1!important;align-self:start!important;justify-self:stretch!important;width:100%!important;max-width:none!important;min-width:0!important;margin:0!important;padding-top:0!important;
        }
        .home-page .home-hero.home-hero-copy-right .home-hero-copy{grid-column:2!important;text-align:right!important;align-items:flex-end!important;}
        .home-page .home-hero.home-hero-copy-left .home-hero-copy{grid-column:1!important;text-align:left!important;align-items:flex-start!important;}
        .home-page .home-hero.home-hero-copy-right .home-login-card{grid-column:1!important;justify-self:start!important;}
        .home-page .home-hero.home-hero-copy-left .home-login-card{grid-column:2!important;justify-self:end!important;}
        .home-page .home-hero .home-login-card{grid-row:1!important;align-self:end!important;position:relative!important;inset:auto!important;width:100%!important;max-width:380px!important;min-width:0!important;height:auto!important;min-height:0!important;margin:0!important;padding:clamp(12px,1.6vw,18px)!important;box-sizing:border-box!important;}
        .home-page .home-hero .home-hero-copy h1{margin-top:0!important;}
      }
      /* Remove unintended pills/tints behind the brand name and both slogan lines. */
      .home-page .home-hero-copy h1,.home-page .home-hero-copy p,
      .home-page .home-nav .home-brand>span,.home-page .home-nav .home-brand>span b,.home-page .home-nav .home-brand>span small{
        background:transparent!important;border:0!important;outline:0!important;box-shadow:none!important;
      }
      .home-page .home-hero-copy p{padding-left:0!important;padding-right:0!important;border-radius:0!important;}
      /* V189: show four member cards at a time; keep portrait photos fully fitted, never cropped. */
      .home-page .home-member-slider{width:100%!important;max-width:100%!important;min-width:0!important;padding-left:26px!important;padding-right:26px!important;overflow:hidden!important;}
      .home-page .home-members{display:flex!important;flex-flow:row nowrap!important;gap:6px!important;width:100%!important;max-width:100%!important;min-width:0!important;padding:7px 2px!important;overflow-x:auto!important;scroll-snap-type:x mandatory!important;scroll-behavior:smooth!important;}
      .home-page .home-member{flex:0 0 calc((100% - 18px)/4)!important;width:calc((100% - 18px)/4)!important;min-width:0!important;max-width:calc((100% - 18px)/4)!important;scroll-snap-align:start!important;overflow:hidden!important;}
      .home-page .home-member-photo{width:100%!important;height:clamp(58px,14vw,112px)!important;min-height:58px!important;padding:3px!important;display:flex!important;align-items:center!important;justify-content:center!important;overflow:hidden!important;}
      .home-page .home-member-photo img{display:block!important;width:100%!important;height:100%!important;max-width:100%!important;max-height:100%!important;object-fit:contain!important;object-position:center center!important;transform:none!important;}
      .home-page .home-member b{display:block!important;max-width:100%!important;padding:4px 2px 0!important;font-size:clamp(8px,1.05vw,13px)!important;line-height:1.15!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;}
      .home-page .home-member small{display:block!important;max-width:100%!important;padding:2px 2px 5px!important;font-size:clamp(7px,.85vw,10px)!important;line-height:1.1!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;}
      @media(max-width:650px){
        .home-page .home-member-slider{padding-left:23px!important;padding-right:23px!important;}
        .home-page .home-members{gap:4px!important;padding:5px 1px!important;}
        .home-page .home-member{flex-basis:calc((100% - 12px)/4)!important;width:calc((100% - 12px)/4)!important;max-width:calc((100% - 12px)/4)!important;}
        .home-page .home-member-photo{height:clamp(54px,17vw,72px)!important;min-height:54px!important;padding:2px!important;}
        .home-page .home-member b{font-size:clamp(8px,2.5vw,10px)!important;padding:3px 1px 0!important;}
        .home-page .home-member small{font-size:clamp(7px,2vw,8px)!important;padding:2px 1px 4px!important;}
        .home-page .home-member-new-badge{font-size:6px!important;padding:2px 3px!important;}
      }
      /* V190: equal Home/Members/Reports/Notices buttons and a clear tri-colour slogan rule. */
      .home-page .home-nav .home-links{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;align-items:stretch!important;gap:6px!important;flex:1 1 560px!important;width:min(100%,720px)!important;max-width:720px!important;min-width:0!important;}
      .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){display:flex!important;align-items:center!important;justify-content:center!important;width:100%!important;min-width:0!important;height:42px!important;min-height:42px!important;max-height:42px!important;padding:0 6px!important;box-sizing:border-box!important;border:1px solid rgba(7,92,55,.32)!important;border-radius:9px!important;overflow:hidden!important;white-space:nowrap!important;text-overflow:ellipsis!important;line-height:1.1!important;font-size:clamp(9px,var(--front-nav-font-size,12px),12px)!important;}
      .home-page .home-hero-copy .home-swoosh{display:block!important;width:clamp(120px,18vw,180px)!important;height:6px!important;margin:12px 0 0!important;padding:0!important;border:0!important;border-radius:999px!important;transform:none!important;background:linear-gradient(90deg,#ff9933 0 33.333%,#ffffff 33.333% 66.666%,#138808 66.666% 100%)!important;box-shadow:0 0 0 1px rgba(7,92,55,.22)!important;}
      .home-page .home-hero.home-hero-copy-right .home-hero-copy .home-swoosh{margin-left:auto!important;margin-right:0!important;}
      .home-page .home-hero.home-hero-copy-left .home-hero-copy .home-swoosh{margin-left:0!important;margin-right:auto!important;}
      .home-page .home-login-card>a.home-login-member,.home-page .home-login-card>a.home-login-admin{
        width:100%!important;min-width:0!important;max-width:100%!important;height:44px!important;min-height:44px!important;max-height:44px!important;
        display:grid!important;grid-template-columns:20px minmax(0,1fr) 20px!important;align-items:center!important;justify-items:stretch!important;gap:9px!important;
        box-sizing:border-box!important;border:1.5px solid rgba(7,92,55,.56)!important;border-radius:10px!important;padding:0 12px!important;margin:6px 0!important;
      }
      .home-page .home-login-card .home-login-icon{width:19px!important;height:19px!important;min-width:19px!important;justify-self:center!important;}
      .home-page .home-login-card .home-login-label{text-align:left!important;min-width:0!important;max-width:100%!important;}
      .home-page .home-login-card .home-login-arrow{width:20px!important;text-align:center!important;justify-self:end!important;}
      @media(max-width:650px){
        .home-page .home-nav .home-links{width:100%!important;max-width:100%!important;flex:0 0 100%!important;gap:4px!important;}
        .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:34px!important;min-height:34px!important;max-height:34px!important;padding:0 3px!important;font-size:clamp(8px,2.5vw,10px)!important;border-radius:7px!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{width:min(100%,260px)!important;max-width:260px!important;height:35px!important;min-height:35px!important;max-height:35px!important;margin:4px auto!important;padding:0 9px!important;gap:7px!important;grid-template-columns:17px minmax(0,1fr) 17px!important;font-size:12px!important;}
        .home-page .home-hero .home-login-card .home-login-icon{width:16px!important;height:16px!important;min-width:16px!important;}
        .home-page .home-hero .home-login-card .home-login-arrow{width:17px!important;font-size:17px!important;}
      }
      /* V191: compact navigation controls, remove excess outlines and soften transparent login buttons. */
      .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:36px!important;min-height:36px!important;max-height:36px!important;padding:0 5px!important;border:.7px solid rgba(7,92,55,.26)!important;border-radius:7px!important;box-shadow:none!important;}
      .home-page .home-login-card>a.home-login-member,.home-page .home-login-card>a.home-login-admin{border:1px solid rgba(7,92,55,.38)!important;background:rgba(255,255,255,.09)!important;box-shadow:none!important;backdrop-filter:blur(1px)!important;}
      .home-page .home-login-card>a.home-login-member:hover,.home-page .home-login-card>a.home-login-admin:hover{background:rgba(255,255,255,.16)!important;border-color:rgba(7,92,55,.52)!important;}
      @media(max-width:650px){
        .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:30px!important;min-height:30px!important;max-height:30px!important;padding:0 3px!important;border:.6px solid rgba(7,92,55,.24)!important;border-radius:6px!important;font-size:clamp(8px,2.3vw,9px)!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{position:relative!important;left:-5px!important;border:1px solid rgba(7,92,55,.36)!important;background:rgba(255,255,255,.08)!important;box-shadow:none!important;}
      }
          /* V192: softer outlines; short, right-aligned mobile login controls; uncropped member photos. */
      .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){border:.5px solid rgba(7,92,55,.14)!important;box-shadow:none!important;}
      .home-page .home-member-photo img{object-fit:contain!important;object-position:center center!important;transform:none!important;}
      @media(max-width:650px){
        .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){border:.5px solid rgba(7,92,55,.12)!important;box-shadow:none!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{
          width:min(72%,220px)!important;max-width:220px!important;min-width:min(160px,100%)!important;height:34px!important;min-height:34px!important;max-height:34px!important;
          position:relative!important;left:0!important;margin:4px 0 4px auto!important;padding:0 9px!important;border:.7px solid rgba(7,92,55,.27)!important;
          background:rgba(255,255,255,.045)!important;box-shadow:none!important;backdrop-filter:none!important;
        }
      }
      /* V193: center login heading; lighten controls; use flat compact home navigation. */
      .home-page .home-login-card h2{text-align:center!important;width:100%!important;margin-left:auto!important;margin-right:auto!important;}
      .home-page .home-login-card>a.home-login-member,.home-page .home-login-card>a.home-login-admin{box-sizing:border-box!important;border:1px solid rgba(7,92,55,.34)!important;background:rgba(255,255,255,.16)!important;box-shadow:none!important;}
      .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:32px!important;min-height:32px!important;max-height:32px!important;border:0!important;outline:0!important;box-shadow:none!important;border-radius:6px!important;}
      @media(max-width:650px){
        .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:27px!important;min-height:27px!important;max-height:27px!important;border:0!important;outline:0!important;box-shadow:none!important;padding-top:0!important;padding-bottom:0!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{height:34px!important;min-height:34px!important;max-height:34px!important;border:1px solid rgba(7,92,55,.34)!important;background:rgba(255,255,255,.16)!important;}
      }
      /* V194: mobile-scale login panel/buttons and genuinely compact borderless nav. */
      @media(max-width:850px){
        .home-page .home-nav .home-links>a,.home-page .home-nav .home-links>a:nth-child(n+3){height:22px!important;min-height:22px!important;max-height:22px!important;padding:0 2px!important;border:0!important;outline:0!important;box-shadow:none!important;font-size:clamp(8px,2.1vw,9px)!important;line-height:1!important;}
        .home-page .home-hero .home-login-card{width:min(100%,340px)!important;max-width:340px!important;min-width:0!important;min-height:0!important;height:auto!important;margin:0 auto!important;padding:9px!important;box-sizing:border-box!important;}
        .home-page .home-login-card h2{text-align:center!important;font-size:14px!important;line-height:1.15!important;margin:0 0 5px!important;padding:0!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{
          width:min(58%,200px)!important;max-width:200px!important;min-width:min(150px,100%)!important;height:30px!important;min-height:30px!important;max-height:30px!important;
          margin:3px 0 3px auto!important;padding:0 7px!important;box-sizing:border-box!important;border:.8px solid rgba(7,92,55,.32)!important;
          background:rgba(255,255,255,.50)!important;box-shadow:none!important;backdrop-filter:none!important;
          grid-template-columns:16px minmax(0,1fr) 16px!important;gap:5px!important;font-size:11px!important;line-height:1.1!important;
        }
        .home-page .home-hero .home-login-card .home-login-icon{width:14px!important;height:14px!important;min-width:14px!important;}
        .home-page .home-login-card .home-login-label{font-size:11px!important;}
        .home-page .home-login-card .home-login-arrow{width:16px!important;font-size:14px!important;}
        .home-page .home-login-card h3{font-size:11px!important;line-height:1.1!important;margin:5px 0 3px!important;padding:5px!important;}
        .home-page .home-login-card ul{margin:3px 0 0!important;padding-left:16px!important;}
        .home-page .home-login-card li{font-size:9px!important;line-height:1.15!important;padding:1px 0!important;}
      }
      @media(max-width:380px){
        .home-page .home-hero .home-login-card{padding:7px!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{width:min(58%,180px)!important;max-width:180px!important;min-width:min(140px,100%)!important;}
      }
      /* V195: align heading over the login-button group on phones; restore broad desktop sizing. */
      @media(min-width:851px){
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{grid-template-columns:minmax(0,1fr) minmax(380px,440px)!important;}
        .home-page .home-hero .home-login-card{width:100%!important;max-width:440px!important;min-width:360px!important;box-sizing:border-box!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{width:100%!important;max-width:100%!important;min-width:0!important;height:48px!important;min-height:48px!important;max-height:48px!important;border:1px solid rgba(7,92,55,.40)!important;background:rgba(255,255,255,.30)!important;}
        .home-page .home-login-card h2{text-align:center!important;width:100%!important;margin-left:auto!important;margin-right:auto!important;}
      }
      @media(max-width:850px){
        .home-page .home-login-card h2{width:min(58%,200px)!important;max-width:200px!important;min-width:min(150px,100%)!important;margin:0 0 5px auto!important;text-align:center!important;}
        .home-page .home-hero .home-login-card>a.home-login-member,.home-page .home-hero .home-login-card>a.home-login-admin{border:1px solid rgba(7,92,55,.40)!important;background:rgba(255,255,255,.50)!important;}
      }
      @media(max-width:380px){
        .home-page .home-login-card h2{width:min(58%,180px)!important;max-width:180px!important;min-width:min(140px,100%)!important;}
      }
      /* V196: Admin-controlled front-page text colors, including login icons/arrows. */
      .home-page .home-hero-copy h1{color:var(--front-hero-title-color,#006132)!important;}
      .home-page .home-hero-copy p{color:var(--front-hero-slogan-color,#064d2d)!important;}
      .home-page .home-login-card h2{color:var(--front-login-heading-color,#075d35)!important;}
      .home-page .home-login-card>a.home-login-member{color:var(--front-member-login-color,#075c37)!important;}
      .home-page .home-login-card>a.home-login-admin{color:var(--front-admin-login-color,#075c37)!important;}
      .home-page .home-login-card .home-login-label,.home-page .home-login-card .home-login-arrow{color:inherit!important;}
      .home-page .home-login-card .home-login-icon{color:inherit!important;stroke:currentColor!important;}
      /* Desktop: keep the Members and Notices panels side by side; phones stack them. */
      @media(min-width:651px){
        .home-page .home-hero .home-login-card{transform:translateY(22px)!important;}
        .home-page .home-hero.home-hero-copy-right,.home-page .home-hero.home-hero-copy-left{min-height:clamp(300px,32vw,390px)!important;}
        .home-page .home-section-grid{display:grid!important;grid-template-columns:minmax(0,1.1fr) minmax(0,.95fr)!important;align-items:start!important;gap:16px!important;}
        .home-page .home-section-grid>.home-panel,.home-page .home-section-grid>.home-notice-panel{min-width:0!important;width:auto!important;max-width:none!important;}
      }
</style>
    <script>
      (function(){
        function setupHomeNoticeTicker(){
          var view=document.querySelector('.home-page .home-notice-ticker-viewport');
          var track=view&&view.querySelector('.home-notice-ticker-track');
          if(!view||!track)return;
          if(!track._noticeSeeds)track._noticeSeeds=Array.prototype.slice.call(track.children).map(function(n){return n.cloneNode(true);});
          var seeds=track._noticeSeeds;if(!seeds.length)return;
          track.innerHTML='';track.style.setProperty('display','flex','important');track.style.setProperty('flex-flow','row nowrap','important');track.style.setProperty('width','max-content','important');track.style.setProperty('max-width','none','important');view.style.setProperty('overflow','hidden','important');view.style.setProperty('white-space','nowrap','important');
          var target=Math.max((view.clientWidth||window.innerWidth||360)*1.25,360),rounds=0;
          while(track.scrollWidth<target&&rounds<32){seeds.forEach(function(seed){track.appendChild(seed.cloneNode(true));});rounds++;}
          Array.prototype.slice.call(track.children).forEach(function(node){var clone=node.cloneNode(true);clone.setAttribute('aria-hidden','true');track.appendChild(clone);});
          var duration=Math.max(24,Math.min(54,Math.round((track.scrollWidth/2)/24)));
          track.style.setProperty('animation','gsHomeNoticeTickerMove '+duration+'s linear infinite','important');
        }
        document.addEventListener('DOMContentLoaded',setupHomeNoticeTicker);
        var resizeTimer;window.addEventListener('resize',function(){clearTimeout(resizeTimer);resizeTimer=setTimeout(setupHomeNoticeTicker,180);});
      })();
    </script>
    <script>
      (function(){
        function applyHomeGrid(){
          var grid=document.querySelector('.home-page .home-section-grid');
          if(!grid)return;
          var desktop=window.matchMedia('(min-width:651px)').matches;
          grid.style.setProperty('display','grid','important');
          grid.style.setProperty('grid-template-columns',desktop?'minmax(0,1.1fr) minmax(0,.95fr)':'minmax(0,1fr)','important');
          grid.style.setProperty('gap',desktop?'16px':'8px','important');
          ['members','notices'].forEach(function(id){var panel=document.getElementById(id);if(panel)panel.style.setProperty('display','block','important');});
        }
        if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',applyHomeGrid);else applyHomeGrid();
        window.addEventListener('resize',applyHomeGrid);
      })();
    </script>
    <div class="home-page">
      <div class="home-top" style="background:<?=$frontHeaderBgTransparent?'transparent':h($frontHeaderBg)?>!important;color:<?=h($frontHeaderText)?>!important"><div class="home-top-left"><span>▣ <?=h(date('l, d F Y'))?></span><span>☎ <?=h($phone)?></span><span>✉ <?=h($email)?></span></div><div class="home-top-right"><strong><?=h($tagline)?></strong><span>◉ WhatsApp</span><span>f Facebook</span><span>▶ YouTube</span></div></div>
      <nav class="home-nav" style="--front-header-bg:<?=$frontHeaderBgTransparent?'transparent':h($frontHeaderBg)?>;--front-header-text:<?=h($frontHeaderText)?>;--front-header-accent:<?=h($frontHeaderAccent)?>;--front-header-artwork:<?= $headerArtworkUrl!=='' ? 'url('.h($headerArtworkUrl).')' : 'none' ?>;--front-header-fit:<?=h($headerArtworkFit)?>;--front-brand-name-size:<?=$brandNameSize?>px;--front-brand-tagline-size:<?=$brandTaglineSize?>px;--front-artwork-only:<?=$headerArtworkOnly?'1':'0'?>;--front-header-height:<?=max(48,min(180,(int)getSetting('front_header_height','76')))?>px;--front-logo-size:<?=max(28,min(130,(int)getSetting('front_logo_size','72')))?>px;--front-nav-font-size:<?=max(8,min(22,(int)getSetting('front_nav_font_size','12')))?>px;--front-nav-item-padding:<?=max(2,min(16,(int)getSetting('front_nav_item_padding','7')))?>px;<?=getSetting('front_show_nav','1')==='1'?'':'display:none!important'?>"><?php if($headerArtworkUrl!==''): ?><img class="home-nav-artwork" src="<?=h($headerArtworkUrl)?>" alt="" aria-hidden="true" onerror="this.style.display='none'"><?php endif; ?><a class="home-brand<?=$headerArtworkOnly?' home-brand-hidden-for-artwork':''?>" href="?route=home"><img src="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>" alt="GS Suraha logo"><span><b><?=h($siteName)?></b><small><?=h($tagline)?></small></span></a><div class="home-links"><a class="home-active" style="<?=getSetting('front_show_nav_home','1')==='1'?'':'display:none!important'?>" href="?route=home">⌂ <?=h(getSetting('front_nav_home','Home'))?></a><a style="<?=getSetting('front_show_nav_members','1')==='1'?'':'display:none!important'?>" href="?route=home#members"><?=h(preg_replace('/[\s⌄⌵▾▼↓˅]+$/u','',getSetting('front_nav_members','Our Members')))?></a><a style="<?=getSetting('front_show_nav_reports','1')==='1'?'':'display:none!important'?>" href="?route=reports"><?=h(preg_replace('/[\s⌄⌵▾▼↓˅]+$/u','',getSetting('front_nav_reports','Reports')))?></a><a style="<?=getSetting('front_show_nav_notices','1')==='1'?'':'display:none!important'?>" href="?route=home#notices"><?=h(preg_replace('/[\s⌄⌵▾▼↓˅]+$/u','',getSetting('front_nav_notices','Notices')))?></a></div></nav>
      <section class="home-hero home-hero-copy-<?=h($heroSide)?>" style="--front-hero-title-color:<?=h($heroTitleColor)?>;--front-hero-slogan-color:<?=h($heroSloganColor)?>;--front-login-heading-color:<?=h($loginHeadingColor)?>;--front-member-login-color:<?=h($memberLoginColor)?>;--front-admin-login-color:<?=h($adminLoginColor)?>;--front-banner-position:<?=h($bannerPosition)?> center;<?=getSetting('front_show_hero','1')==='1'?'':'display:none!important'?>"><div class="home-hero-copy"><h1><?=h(getSetting('front_hero_title',$siteName))?></h1><p><?=nl2br(h(getSetting('front_hero_slogan','“सदस्यों का विश्वास,\nसमिति का साथ”')))?></p><div class="home-swoosh"></div></div><aside class="home-login-card" style="<?=getSetting('front_show_login','1')==='1'?'':'display:none!important'?>"><h2><?=h(getSetting('front_login_heading','सदस्य एवं Admin Login'))?></h2><a class="home-login-member" href="?route=member-login"><svg class="home-login-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c.7-3.7 3-5.6 7-5.6s6.3 1.9 7 5.6"/></svg><span class="home-login-label"><?=h(getSetting('front_member_login_label','Member Login'))?></span><span class="home-login-arrow">›</span></a><a class="home-login-admin" href="?route=admin-login"><svg class="home-login-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 20 6v5.5c0 4.8-3.3 7.8-8 9.5-4.7-1.7-8-4.7-8-9.5V6z"/><path d="m8.5 12 2.3 2.3 4.8-5"/></svg><span class="home-login-label"><?=h(getSetting('front_admin_login_label','Admin Login'))?></span><span class="home-login-arrow">›</span></a><h3><?=h(getSetting('front_feature_heading','हमारी समिति की विशेषताएं'))?></h3><ul><?php foreach([1,2,3] as $fi): $fallback=['सुरक्षित बचत और पारदर्शिता','सहयोग से समृद्धि का संकल्प','सभी के लिए सहायता'][$fi-1]; ?><li><?=h(getSetting('front_hero_promise_'.$fi,$fallback))?></li><?php endforeach; ?></ul></aside></section>
      <section class="home-section-grid"><div id="members" class="home-panel"><div class="home-panel-head"><h2>♟ <?=h(getSetting('front_members_title','हमारे सदस्य'))?></h2><a href="?route=home#members"><?=h(getSetting('front_members_link_text','सभी सदस्य देखें »'))?></a></div><div class="home-member-slider"><button class="home-member-arrow home-member-prev" type="button" aria-label="पिछले सदस्य" onclick="scrollHomeMembers(-1)">‹</button><div class="home-members" id="homeMembersTrack"><?php if($homeMembers): foreach($homeMembers as $mi=>$hm): ?><div class="home-member"><div class="home-member-photo"><?php if($mi===0): ?><span class="home-member-new-badge">नया सदस्य</span><?php endif; ?><?php if(!empty($hm['photo'])):?><img src="<?=memberFileUrl($hm['photo'])?>" alt="<?=h($hm['name'])?>" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span class="home-photo-fallback" style="display:none">👤</span><?php else:?><span>👤</span><?php endif;?></div><b><?=h($hm['name'])?></b><small>सदस्य क्र. <?=h($hm['code'])?></small></div><?php endforeach; else: ?><div class="home-empty">अभी सदस्य सूची उपलब्ध नहीं है।</div><?php endif; ?></div><button class="home-member-arrow home-member-next" type="button" aria-label="अगले सदस्य" onclick="scrollHomeMembers(1)">›</button></div></div><div id="notices" class="home-panel home-notice-panel">
<div class="home-panel-head"><h2>📢 <?=h(getSetting('front_notice_title','समिति की खबरें एवं सूचनाएं'))?></h2></div>
<div class="home-notices-list">
<?php if($homeNotices): foreach($homeNotices as $hn): ?>
  <article class="home-notice-row">
    <div class="home-notice-icon">📢</div>
    <div class="home-notice-body">
      <b><?=h($hn['title']?:'महत्वपूर्ण सूचना')?></b>
      <p><?=h(trim(preg_replace('/\s+/u',' ',(string)$hn['body'])))?></p>
    </div>
    <time><?=h(date('d-m-Y',strtotime((string)$hn['created_at'])))?></time>
  </article>
<?php endforeach; else: ?>
  <div class="home-empty">समिति की नई सूचनाएं जल्द यहां दिखाई देंगी।</div>
<?php endif; ?>
</div>
<div class="home-latest-contribution home-notice-ticker" role="region" aria-label="Notice ticker">
  <div class="home-latest-contribution-title home-notice-ticker-title">📢 चलती सूचना</div>
  <div class="home-latest-contribution-viewport home-notice-ticker-viewport">
    <div class="home-latest-contribution-track home-notice-ticker-track" id="homeNoticeTickerTrack">
<?php if($homeNotices): foreach($homeNotices as $hn): ?>
      <span class="home-latest-contribution-item home-notice-ticker-item"><b><?=h($hn['title']?:'सूचना')?></b><span>— <?=h(trim(preg_replace('/\s+/u',' ',(string)$hn['body'])))?></span></span>
<?php endforeach; foreach($homeNotices as $hn): ?>
      <span class="home-latest-contribution-item home-notice-ticker-item" aria-hidden="true"><b><?=h($hn['title']?:'सूचना')?></b><span>— <?=h(trim(preg_replace('/\s+/u',' ',(string)$hn['body'])))?></span></span>
<?php endforeach; else: ?>
      <span class="home-latest-contribution-item home-notice-ticker-item"><b>सूचना</b><span>— समिति की नई सूचनाएं जल्द यहां दिखाई देंगी।</span></span>
<?php endif; ?>
    </div>
  </div>
</div>
</div></section>
<script>
(function(){
  function forceFrontPanels(){
    var grid=document.querySelector('.home-page .home-section-grid');
    if(!grid)return;
    var desktop=window.innerWidth>=651;
    grid.style.setProperty('display','grid','important');
    grid.style.setProperty('grid-template-columns',desktop?'minmax(0,1.1fr) minmax(0,.95fr)':'minmax(0,1fr)','important');
    grid.style.setProperty('gap',desktop?'16px':'8px','important');
    ['members','notices'].forEach(function(id){var panel=document.getElementById(id);if(panel)panel.style.setProperty('display','block','important');});
  }
  forceFrontPanels();window.addEventListener('load',forceFrontPanels);window.addEventListener('resize',forceFrontPanels);
})();
</script>

      <section class="home-latest-contribution" aria-label="<?=h($latestContributionTitle)?>" style="<?=getSetting('front_show_latest_contribution','1')==='1'?'':'display:none!important'?>"><div class="home-latest-contribution-title">💰 <?=h($latestContributionTitle)?></div><div class="home-latest-contribution-viewport"><div class="home-latest-contribution-track"><?php if($homeContributionActivity): foreach($homeContributionActivity as $hc): $latestCopy=str_replace(['{date}','{site}'],[date('d M Y',strtotime((string)$hc['created_at'])),$siteName],$latestContributionTemplate); ?><span class="home-latest-contribution-item"><?=h($latestCopy)?></span><?php endforeach; foreach($homeContributionActivity as $hc): $latestCopy=str_replace(['{date}','{site}'],[date('d M Y',strtotime((string)$hc['created_at'])),$siteName],$latestContributionTemplate); ?><span class="home-latest-contribution-item" aria-hidden="true"><?=h($latestCopy)?></span><?php endforeach; else: ?><span class="home-latest-contribution-item"><?=h($latestContributionEmpty)?></span><span class="home-latest-contribution-item" aria-hidden="true"><?=h($latestContributionEmpty)?></span><?php endif; ?></div></div></section>
      <section id="about" class="home-about" style="<?=getSetting('front_show_about','1')==='1'?'':'display:none!important'?>;margin:0 clamp(14px,3vw,32px) 18px;padding:20px 24px;background:#fff;border-radius:14px;box-shadow:0 3px 13px rgba(12,67,38,.12);display:grid;grid-template-columns:1.3fr 1fr;gap:24px"><div><h2 style="margin:0 0 8px;color:#075d35"><?=h(getSetting('front_about_title','About Us / हमारे बारे में'))?></h2><p style="margin:0;color:#53685c;line-height:1.6"><?=nl2br(h(getSetting('front_about_body','GS Suraha Sahyog Samiti सदस्यों के सहयोग, सुरक्षित बचत और पारदर्शी सेवा के लिए बनाया गया platform है।')))?></p></div><div id="contact" style="border-left:1px solid #d6e8da;padding-left:22px"><h2 style="margin:0 0 8px;color:#075d35"><?=h(getSetting('front_contact_title','Contact Us / संपर्क'))?></h2><p style="margin:5px 0">☎ <?=h($phone)?></p><p style="margin:5px 0">✉ <?=h($email)?></p><p style="margin:5px 0;color:#53685c"><?=nl2br(h($address))?></p></div></section>
      <section class="home-contribution" style="<?=getSetting('front_show_contribution','1')==='1'?'':'display:none!important'?>;margin:0 clamp(14px,3vw,32px) 18px;padding:18px 22px;background:linear-gradient(120deg,#e3f7e9,#f4fff6);border:1px solid #c8e8d1;border-radius:14px;box-shadow:0 3px 13px rgba(12,67,38,.10);display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap"><div><h2 style="margin:0 0 6px;color:#075d35"><?=h(getSetting('front_contribution_heading','🤝 Contribution / सदस्य योगदान'))?></h2><p style="margin:0;color:#53685c;line-height:1.5"><?=nl2br(h(getSetting('front_contribution_body','समिति के सहयोग और विकास में अपना योगदान दें। अपना contribution देखने या जमा करने के लिए सदस्य लॉगिन करें।')))?></p></div><a href="?route=member-login" style="display:inline-block;background:#08783e;color:#fff;text-decoration:none;font-weight:700;padding:11px 18px;border-radius:9px;white-space:nowrap"><?=h(getSetting('front_contribution_button','Contribution के लिए Member Login →'))?></a></section>
      <section class="home-features" style="<?=getSetting('front_show_features','1')==='1'?'':'display:none!important'?>"><div class="home-feature"><span>🛡</span><?=h(getSetting('front_feature_1','सुरक्षित एवं विश्वसनीय प्लेटफॉर्म'))?></div><div class="home-feature"><span>🤝</span><?=h(getSetting('front_feature_2','सहयोग से समृद्धि'))?></div><div class="home-feature"><span>♟</span><?=h(getSetting('front_feature_3','सशक्त सदस्य, समृद्ध समिति'))?></div><div class="home-feature"><span>☎</span><?=h(getSetting('front_feature_4','24×7 सहायता'))?></div></section>
      <footer class="home-footer"><div><?=h($siteName)?> <a href="?route=about"><?=h(getSetting('front_footer_about_label','About'))?></a><a href="?route=contact"><?=h(getSetting('front_footer_contact_label','Contact'))?></a></div><small>© <?=date('Y')?> <?=h($siteName)?>. All Rights Reserved.</small></footer>
    </div>
    <?php $c=ob_get_clean(); layout('Home',$c); exit;
}

// Public member directory. This is intentionally separate from the authenticated admin/member ?route=members page.
if($route==='public-members'){
    $publicMembers=[]; $pmq=$db->query("SELECT id,code,name,father_name,photo,status FROM members ORDER BY id ASC LIMIT 100");
    while($pmq && ($pm=$pmq->fetchArray(SQLITE3_ASSOC))) $publicMembers[]=$pm;
    ob_start(); ?><style>
    .public-members-page{max-width:1180px;margin:0 auto;padding:24px 16px}.public-members-page h1{color:#075d35;margin:0 0 6px}.public-members-page .sub{color:#66756d;margin:0 0 20px}.public-members-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:15px}.public-member-card{background:#fff;border:1px solid #dcebe1;border-radius:13px;overflow:hidden;box-shadow:0 4px 14px rgba(0,70,38,.10);text-align:center}.public-member-photo{height:190px;background:linear-gradient(135deg,#edf7f0,#d9eee0);display:flex;align-items:center;justify-content:center}.public-member-photo img{width:100%;height:100%;object-fit:cover}.public-member-photo span{font-size:70px}.public-member-card b{display:block;font-size:17px;padding:10px 6px 2px}.public-member-card small{display:block;color:#63736a;padding:0 6px 13px}.public-members-back{display:inline-block;margin:0 0 18px;background:#08783e;color:#fff;border-radius:8px;padding:10px 15px;text-decoration:none;font-weight:700}@media(max-width:850px){.public-members-grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.public-members-grid{grid-template-columns:repeat(2,1fr)}.public-member-photo{height:145px}.public-member-card b{font-size:14px}}
    </style><div class="public-members-page"><a class="public-members-back" href="?route=home">← Front Page</a><h1>हमारे सदस्य / Our Members</h1><p class="sub">GS Suraha Sahyog Samiti के registered members.</p><div class="public-members-grid"><?php if($publicMembers): foreach($publicMembers as $pm): ?><article class="public-member-card"><div class="public-member-photo"><?php if(!empty($pm['photo'])):?><img src="<?=memberFileUrl($pm['photo'])?>" alt="<?=h($pm['name'])?>" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><span style="display:none">👤</span><?php else:?><span>👤</span><?php endif;?></div><b><?=h($pm['name'])?></b><small>सदस्य क्र. <?=h($pm['code'])?></small></article><?php endforeach; else: ?><p>अभी कोई member उपलब्ध नहीं है।</p><?php endif; ?></div></div><?php $c=ob_get_clean(); layout('Our Members',$c); exit;
}


// Public legal / information pages. These routes intentionally work without login.
$publicLegalRoutes=['terms','privacy','refund-policy','disclaimer','acceptable-use','cookie-policy','whatsapp-policy','payment-terms','about','contact'];
if(in_array($route,$publicLegalRoutes,true)){
    $legalTitles=[
      'terms'=>['Terms of Use / उपयोग की शर्तें','Terms of Use'],
      'privacy'=>['Privacy Policy / गोपनीयता नीति','Privacy Policy'],
      'refund-policy'=>['Refund & Cancellation Policy / रिफंड एवं रद्दीकरण नीति','Refund & Cancellation'],
      'disclaimer'=>['Disclaimer / अस्वीकरण','Disclaimer'],
      'acceptable-use'=>['Acceptable Use Policy / स्वीकार्य उपयोग नीति','Acceptable Use'],
      'cookie-policy'=>['Cookie Policy / कुकी नीति','Cookie Policy'],
      'whatsapp-policy'=>['WhatsApp Messaging Policy / व्हाट्सऐप नीति','WhatsApp Policy'],
      'payment-terms'=>['Payment Terms / भुगतान शर्तें','Payment Terms'],
      'about'=>['About Us / हमारे बारे में','About'],
      'contact'=>['Contact Us / संपर्क करें','Contact'],
    ];
    [$legalTitle,$shortTitle]=$legalTitles[$route];
    $siteName=(string)getSetting('site_name','GS Suraha Finance');
    $tagline=(string)getSetting('society_tagline','Finance Co-operative Society');
    $phone=trim((string)getSetting('contact_phone',''));
    $email=trim((string)getSetting('contact_email',''));
    $address=trim((string)getSetting('contact_address',''));
    $customTerms=trim((string)getSetting('terms_text',''));
    $customPrivacy=trim((string)getSetting('privacy_text',''));
    ob_start(); ?>
    <style>
      .legal-wrap{max-width:1050px;margin:0 auto;padding:22px 14px 42px}.legal-hero{background:linear-gradient(135deg,#06265b,#0b65d5);color:#fff;border-radius:18px;padding:26px 24px;margin-bottom:16px;box-shadow:0 12px 35px rgba(15,23,42,.12)}
      .legal-hero h1{margin:0 0 6px;font-size:25px}.legal-hero p{margin:0;opacity:.9}.legal-nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px}.legal-nav a{padding:9px 12px;border:1px solid #dbe3ef;border-radius:999px;background:#fff;color:#17324d;text-decoration:none;font-size:12px;font-weight:700}.legal-nav a.active{background:#0b65d5;color:#fff;border-color:#0b65d5}.legal-card{background:#fff;border:1px solid #e3e8f0;border-radius:16px;padding:22px;box-shadow:0 7px 24px rgba(15,23,42,.06)}
      .legal-card h2{font-size:18px;margin:20px 0 8px;color:#06265b}.legal-card h2:first-child{margin-top:0}.legal-card h3{font-size:14px;margin:18px 0 6px;color:#17324d}.legal-card p,.legal-card li{font-size:13px;line-height:1.75;color:#475569}.legal-card ul{padding-left:20px}.legal-note{background:#f5f9ff;border-left:4px solid #0b65d5;padding:12px 14px;border-radius:8px;margin:14px 0;color:#334155;font-size:12px}.legal-contact{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.legal-contact div{border:1px solid #e3e8f0;border-radius:12px;padding:14px;background:#fafcff}.legal-contact b{display:block;margin-bottom:5px;color:#06265b}@media(max-width:700px){.legal-contact{grid-template-columns:1fr}.legal-wrap{padding:14px 10px 30px}.legal-card{padding:16px}.legal-hero{padding:20px 16px}}
    </style>
    <div class="legal-wrap">
      <div class="legal-hero"><h1><?=h($legalTitle)?></h1><p><?=h($siteName)?> · <?=h($tagline)?></p></div>
      <nav class="legal-nav">
        <?php foreach($legalTitles as $rk=>$rv): ?><a class="<?= $rk===$route?'active':'' ?>" href="?route=<?=h($rk)?>"><?=h($rv[1])?></a><?php endforeach; ?>
      </nav>
      <article class="legal-card">
      <?php if($route==='terms'): ?>
        <?php if($customTerms!==''): ?><div class="legal-note">Admin द्वारा सेट की गई Terms & Conditions नीचे लागू हैं।</div><div><?=nl2br(h($customTerms))?></div><?php else: ?>
        <h2>1. Acceptance of Terms</h2><p>इस वेबसाइट, member portal और उपलब्ध services का उपयोग करने पर आप इन Terms of Use से सहमत माने जाएंगे। यदि आप सहमत नहीं हैं तो service का उपयोग न करें।</p>
        <h2>2. Account & Member Information</h2><p>सदस्य को सही नाम, mobile number, address और अन्य आवश्यक जानकारी देनी होगी। Login credentials और OTP को सुरक्षित रखना सदस्य की जिम्मेदारी है।</p>
        <h2>3. Financial Information</h2><p>Loan, EMI, contribution, payment और outstanding figures records के आधार पर प्रदर्शित किए जाते हैं। अंतिम financial verification संस्था के records के अनुसार होगी।</p>
        <h2>4. Payments</h2><p>Online payment के दौरान third-party payment gateway/UPI provider की terms भी लागू हो सकती हैं। Payment confirmation मिलने तक transaction को pending माना जा सकता है।</p>
        <h2>5. Prohibited Use</h2><ul><li>Unauthorized access या किसी दूसरे member account का उपयोग।</li><li>False information, fraudulent transaction या misleading documents।</li><li>System को damage, overload या security controls को bypass करने का प्रयास।</li></ul>
        <h2>6. Service Availability</h2><p>Maintenance, hosting failure, network issue, third-party API या security controls के कारण service अस्थायी रूप से unavailable हो सकती है।</p>
        <h2>7. Changes</h2><p>संस्था आवश्यकता के अनुसार Terms को update कर सकती है। Updated version वेबसाइट पर प्रकाशित होने के बाद लागू होगा।</p>
        <h2>8. Contact</h2><p>किसी प्रश्न या शिकायत के लिए Contact Us page पर दिए गए माध्यम का उपयोग करें।</p>
        <?php endif; ?>
      <?php elseif($route==='privacy'): ?>
        <?php if($customPrivacy!==''): ?><div class="legal-note">Admin द्वारा सेट की गई Privacy Policy नीचे लागू है।</div><div><?=nl2br(h($customPrivacy))?></div><?php else: ?>
        <h2>1. Information We Collect</h2><p>हम member name, member ID, mobile number, address, loan/EMI/contribution records और service use से जुड़ी आवश्यक information collect कर सकते हैं।</p>
        <h2>2. How Information Is Used</h2><ul><li>Account और member verification के लिए।</li><li>Loan, EMI, contribution और payment records maintain करने के लिए।</li><li>Required notifications, receipts और WhatsApp/SMS communication के लिए।</li><li>Security, fraud prevention और audit के लिए।</li></ul>
        <h2>3. Sharing</h2><p>Information केवल आवश्यक service providers, payment/communication providers, authorized staff या कानूनन आवश्यक authorities के साथ आवश्यकता के अनुसार share की जा सकती है।</p>
        <h2>4. Security</h2><p>हम reasonable technical और organizational safeguards इस्तेमाल करते हैं, लेकिन कोई भी internet system 100% secure होने की guarantee नहीं देता।</p>
        <h2>5. Data Retention</h2><p>Financial और member records को applicable business, accounting, audit और legal requirements के अनुसार रखा जा सकता है।</p>
        <h2>6. Your Requests</h2><p>अपने personal information से जुड़े प्रश्न या correction request के लिए Contact Us page से संपर्क करें।</p>
        <?php endif; ?>
      <?php elseif($route==='refund-policy'): ?>
        <h2>1. General Policy</h2><p>Payment successful होने के बाद refund automatic नहीं होता। Refund/cancellation संस्था के transaction records और applicable rules के अनुसार review किया जाएगा।</p>
        <h2>2. Duplicate / Failed Transactions</h2><p>Duplicate debit या payment gateway failure की स्थिति में transaction reference, date और amount के साथ support को सूचना दें।</p>
        <h2>3. Loan / EMI Payments</h2><p>Loan या EMI payment को गलत account में post होने से बचाने के लिए correct Member ID/reference देना आवश्यक है। Reversal केवल verification के बाद किया जाएगा।</p>
        <h2>4. Processing</h2><p>Approved refund का actual credit time payment provider/bank पर निर्भर कर सकता है।</p>
        <h2>5. Contact</h2><p>Refund request के साथ Member ID, amount, date और transaction/reference number दें।</p>
      <?php elseif($route==='disclaimer'): ?>
        <h2>1. Information Disclaimer</h2><p>Website पर उपलब्ध information सामान्य administrative और member-service purposes के लिए है। Displayed information को final legal, tax या financial advice नहीं माना जाना चाहिए।</p>
        <h2>2. Third-Party Services</h2><p>Payment gateways, WhatsApp, SMS, hosting और अन्य third-party services अपने terms, availability और policies के अनुसार operate करते हैं।</p>
        <h2>3. Accuracy</h2><p>हम records को accurate रखने का प्रयास करते हैं, लेकिन technical or data-entry errors संभव हैं। महत्वपूर्ण transaction के लिए official record से verification करें।</p>
      <?php elseif($route==='acceptable-use'): ?>
        <h2>Permitted Use</h2><p>Portal का उपयोग केवल legitimate member, staff और administrative activities के लिए करें।</p>
        <h2>Not Allowed</h2><ul><li>Credential sharing या unauthorized access.</li><li>Fake member/account creation.</li><li>Malware, automated abuse, scraping या excessive requests.</li><li>Fraudulent payment, forged document या false identity.</li></ul>
      <?php elseif($route==='cookie-policy'): ?>
        <h2>Cookies & Session Data</h2><p>Website login session, security token और आवश्यक preferences के लिए browser storage/cookies का उपयोग कर सकती है। ये cookies service को सुरक्षित और functional रखने के लिए आवश्यक हो सकती हैं।</p>
        <h2>Third-Party Cookies</h2><p>कुछ third-party services अपनी cookies या tracking technologies इस्तेमाल कर सकती हैं। उनकी policies अलग से लागू हो सकती हैं।</p>
      <?php elseif($route==='whatsapp-policy'): ?>
        <h2>WhatsApp Messaging</h2><p>WhatsApp messages केवल configured business/communication workflows के लिए भेजे जाते हैं। Business-initiated messages Meta/WhatsApp template और policy requirements के अधीन हो सकते हैं।</p>
        <h2>Opt-out / Support</h2><p>यदि आपको communication बंद करवानी है या गलत message मिला है, Contact Us के माध्यम से request करें।</p>
        <h2>Media & Documents</h2><p>Payment slips और documents भेजने के लिए member का सही mobile/WhatsApp number और configured provider permissions आवश्यक हैं।</p>
      <?php elseif($route==='payment-terms'): ?>
        <h2>Payment Processing</h2><p>Payment page पर दिखाई गई amount, reference और status transaction records से जुड़े हैं। Gateway/UPI confirmation मिलने के बाद record update किया जा सकता है।</p>
        <h2>Charges</h2><p>यदि किसी payment provider या bank द्वारा separate processing charges लगाए जाते हैं, वे provider की policy के अनुसार होंगे।</p>
        <h2>Receipt</h2><p>Successful payment के बाद उपलब्ध receipt को अपने records के लिए सुरक्षित रखें।</p>
      <?php elseif($route==='about'): ?>
        <h2><?=h($siteName)?></h2><p><?=h($tagline)?>. यह portal member management, contribution, loan, EMI, payment receipt और communication workflows को एक जगह manage करने के लिए बनाया गया है।</p>
        <div class="legal-note">Website पर उपलब्ध facilities आपके configured organization settings और applicable policies के अनुसार काम करती हैं।</div>
      <?php elseif($route==='contact'): ?>
        <h2>Contact / संपर्क</h2><div class="legal-contact"><div><b>Phone</b><?=h($phone!==''?$phone:'Admin द्वारा configure नहीं किया गया')?></div><div><b>Email</b><?=h($email!==''?$email:'Admin द्वारा configure नहीं किया गया')?></div><div><b>Address</b><?=h($address!==''?$address:'Admin द्वारा configure नहीं किया गया')?></div></div><div class="legal-note" style="margin-top:16px">Payment/refund support के लिए Member ID और transaction/reference number साथ में दें।</div>
      <?php endif; ?>
      </article>
    </div>
    <?php $c=ob_get_clean(); layout($shortTitle,$c); exit;
}

if($route==='verify-member'){
    $code=trim((string)($_GET['code'] ?? ''));
    $st=$db->prepare("SELECT id,code,name,mobile,address,photo,status FROM members WHERE code=? LIMIT 1");
    $st->bindValue(1,$code,SQLITE3_TEXT);
    $m=$st->execute()->fetchArray(SQLITE3_ASSOC);
    $title='Member Verification / सदस्य सत्यापन';
    ob_start(); ?>
    <style>
      .verify-wrap{min-height:100vh;background:#f5f7fb;padding:28px 16px;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center}
      .verify-card{width:min(680px,100%);background:#fff;border:1px solid #d9dee8;border-radius:18px;overflow:hidden;box-shadow:0 12px 40px rgba(15,23,42,.10)}
      .verify-head{padding:18px 22px;border-top:7px solid #ff9933;border-bottom:4px solid #138808;display:flex;align-items:center;gap:14px;background:linear-gradient(90deg,#fff8ef,#fff,#f1fff3)}
      .verify-head img{width:58px;height:58px;object-fit:contain;border-radius:10px}.verify-head h1{font-size:20px;margin:0}.verify-head p{margin:3px 0 0;color:#64748b;font-size:12px}.verify-body{padding:22px}.verify-ok{display:inline-flex;padding:7px 12px;border-radius:999px;background:#e8f7ed;color:#137333;font-weight:700;font-size:12px;margin-bottom:16px}.verify-grid{display:grid;grid-template-columns:120px 1fr;gap:20px;align-items:start}.verify-photo{width:120px;height:150px;border:1px solid #d7dce5;border-radius:10px;overflow:hidden;background:#f8fafc;display:flex;align-items:center;justify-content:center}.verify-photo img{width:100%;height:100%;object-fit:cover}.verify-photo span{font-size:44px}.verify-row{padding:9px 0;border-bottom:1px solid #e5e7eb;display:flex;justify-content:space-between;gap:15px}.verify-row span{color:#64748b;font-size:12px}.verify-row b{text-align:right;font-size:14px}.verify-note{margin-top:18px;padding:12px;border:1px solid #d8e6dd;border-radius:10px;background:#f5fbf7;font-size:12px;color:#475569}@media(max-width:520px){.verify-grid{grid-template-columns:1fr}.verify-photo{width:100px;height:125px}.verify-row{display:block}.verify-row b{display:block;text-align:left;margin-top:3px}}
    </style>
    <div class="verify-wrap"><div class="verify-card">
      <div class="verify-head"><img src="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>" alt="GS Suraha"><div><h1>GS Suraha Sahyog Samiti</h1><p>Finance Co-operative Society · Member Verification</p></div></div>
      <?php if(!$m): ?>
        <div class="verify-body"><div class="alert danger">Member not found / सदस्य नहीं मिला</div><p>Please scan a valid GS Suraha Member QR code.</p></div>
      <?php else: ?>
        <div class="verify-body"><div class="verify-ok">✓ VERIFIED MEMBER / सत्यापित सदस्य</div><div class="verify-grid"><div class="verify-photo"><?php if(!empty($m['photo'])):?><img src="<?=memberFileUrl($m['photo'])?>" alt="Member photo"><?php else:?><span>👤</span><?php endif;?></div><div>
          <div class="verify-row"><span>Name / नाम</span><b><?=h($m['name'])?></b></div>
          <div class="verify-row"><span>Member ID / सदस्य आईडी</span><b><?=h($m['code'])?></b></div>
          <div class="verify-row"><span>Mobile / मोबाइल</span><b><?=h($m['mobile'])?></b></div>
          <div class="verify-row"><span>Status / स्थिति</span><b><?=h($m['status'])?></b></div>
          <div class="verify-row"><span>Address / पता</span><b><?=h($m['address'] ?: '—')?></b></div>
        </div></div><div class="verify-note">यह पेज केवल सदस्य की पहचान सत्यापित करने के लिए है। Loan, contribution या अन्य financial details यहाँ नहीं दिखाई जातीं।</div></div>
      <?php endif; ?>
    </div></div>
    <?php $c=ob_get_clean(); layout($title,$c); exit;
}

function createWhatsAppLoginOtp(int $userId, string $mobile, string $displayName=''): array {
    global $db;
    $mobile=trim($mobile);
    if($mobile==='') return [false,'Member का WhatsApp/mobile number दर्ज नहीं है।'];
    $digits=memberContactDigits($mobile);
    if($digits==='') return [false,'Member का WhatsApp/mobile number सही नहीं है।'];
    $now=time();
    $recent=$db->prepare("SELECT last_sent_at FROM whatsapp_login_otps WHERE user_id=? ORDER BY id DESC LIMIT 1");
    $recent->bindValue(1,$userId,SQLITE3_INTEGER); $rr=$recent->execute()->fetchArray(SQLITE3_ASSOC);
    if($rr && ($now-(int)$rr['last_sent_at'])<60) return [false,'OTP पहले ही भेजा जा चुका है। 60 सेकंड बाद फिर भेजें।'];
    $otp=(string)random_int(100000,999999);
    $hash=password_hash($otp,PASSWORD_DEFAULT);
    $expires=$now+300;
    $db->exec('DELETE FROM whatsapp_login_otps WHERE user_id='.(int)$userId.' OR expires_at<'.$now);
    $st=$db->prepare("INSERT INTO whatsapp_login_otps(user_id,mobile,otp_hash,expires_at,attempts,last_sent_at) VALUES(?,?,?,?,0,?)");
    $st->bindValue(1,$userId,SQLITE3_INTEGER); $st->bindValue(2,$digits,SQLITE3_TEXT); $st->bindValue(3,$hash,SQLITE3_TEXT); $st->bindValue(4,$expires,SQLITE3_INTEGER); $st->bindValue(5,$now,SQLITE3_INTEGER);
    if(!$st->execute()) return [false,'OTP record save नहीं हो पाया।'];
    $name=$displayName!==''?$displayName:'Member';
    $message="नमस्कार {$name} जी, 🙏\nGS Suraha login verification OTP: {$otp}\nयह OTP 5 मिनट तक मान्य है।\nOTP किसी के साथ साझा न करें।\nGS Suraha Sahyog Samiti";
    [$ok,$msg]=sendWhatsAppMeta($digits,$message);
    if(!$ok){ $db->exec('DELETE FROM whatsapp_login_otps WHERE user_id='.(int)$userId); return [false,$msg]; }
    return [true,'WhatsApp API ने OTP संदेश स्वीकार किया है। यदि OTP नहीं मिला, पहले WhatsApp पर 8877775963 को Hi भेजें, फिर Resend OTP करें।'];
}

function verifyWhatsAppLoginOtp(int $userId, string $otp): array {
    global $db;
    $otp=preg_replace('/\D+/','',$otp);
    if(strlen($otp)!==6) return [false,'6 अंकों का OTP डालें।'];
    $st=$db->prepare("SELECT * FROM whatsapp_login_otps WHERE user_id=? ORDER BY id DESC LIMIT 1");
    $st->bindValue(1,$userId,SQLITE3_INTEGER); $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$r) return [false,'OTP नहीं मिला। नया OTP भेजें।'];
    if((int)$r['expires_at']<time()) return [false,'OTP की समय-सीमा समाप्त हो गई है। नया OTP भेजें।'];
    if((int)$r['attempts']>=5) return [false,'बहुत अधिक गलत OTP प्रयास हो चुके हैं। नया OTP भेजें।'];
    if(!password_verify($otp,(string)$r['otp_hash'])){
        $up=$db->prepare("UPDATE whatsapp_login_otps SET attempts=attempts+1 WHERE id=?"); $up->bindValue(1,(int)$r['id'],SQLITE3_INTEGER); $up->execute();
        return [false,'गलत OTP। कृपया फिर से प्रयास करें।'];
    }
    $up=$db->prepare("UPDATE whatsapp_login_otps SET verified_at=? WHERE id=?"); $up->bindValue(1,time(),SQLITE3_INTEGER); $up->bindValue(2,(int)$r['id'],SQLITE3_INTEGER); $up->execute();
    return [true,'OTP verified.'];
}

if($route==='login'){
    if(user() && ($loginPortal==='all' || ($loginPortal==='member' && user()['role']==='member') || ($loginPortal==='admin' && in_array(user()['role'],['admin','staff'],true)))) redirect(user()['role']==='member'?'member-dashboard':'dashboard');
    if(user() && $loginPortal!=='all') {
        $currentRole=user()['role']==='member'?'Member':(user()['role']==='staff'?'Staff':'Admin');
        $targetRole=$loginPortal==='member'?'Member':'Admin / Staff';
        $targetRoute=$loginPortal==='member'?'member-login':'admin-login';
        ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Switch account | GS Suraha</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f0f7f2;font:16px Arial,sans-serif;color:#173b29}.card{box-sizing:border-box;width:min(92vw,480px);padding:32px;border-radius:18px;background:#fff;box-shadow:0 12px 40px #17472b20;text-align:center}.card h1{color:#08783e}.card p{line-height:1.6;color:#53685c}.btn{display:block;margin:12px 0;padding:13px;border-radius:9px;background:#08783e;color:#fff;text-decoration:none;font-weight:700}.back{background:#eff6f0;color:#08783e}</style></head><body><main class="card"><h1>Already logged in</h1><p>This browser is currently signed in as <b><?=h($currentRole)?></b>. To open the <?=h($targetRole)?> login, first sign out. Signing out here will also sign out the other tabs in this browser.</p><a class="btn" href="?route=logout&amp;next=<?=h($targetRoute)?>">Sign out and continue to <?=h($targetRole)?> login</a><a class="btn back" href="?route=<?=user()['role']==='member'?'member-dashboard':'dashboard'?>">Return to current dashboard</a></main></body></html><?php exit;
    }
    $error=''; $otpMode=false;
    $otpLoginEnabled=($loginPortal==='member' && getSetting('member_whatsapp_otp_enabled','1')==='1');
    $pendingUserId=(int)($_SESSION['whatsapp_otp_user_id']??0);
    // If an admin disables OTP, discard any pending OTP challenge and show normal login.
    if(!$otpLoginEnabled){
        unset($_SESSION['whatsapp_otp_user_id'],$_SESSION['whatsapp_otp_username']);
        $pendingUserId=0;
    } elseif($pendingUserId>0 && isset($_SESSION['whatsapp_otp_username'])) {
        $otpMode=true;
    }
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=$_POST['action']??'login';
        if($action==='verify_otp' && $pendingUserId>0){
            [$ok,$msg]=verifyWhatsAppLoginOtp($pendingUserId,(string)($_POST['otp']??''));
            if($ok){
                $st=$db->prepare("SELECT * FROM users WHERE id=? AND role='member' LIMIT 1"); $st->bindValue(1,$pendingUserId,SQLITE3_INTEGER); $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
                if(!$r){ unset($_SESSION['whatsapp_otp_user_id'],$_SESSION['whatsapp_otp_username']); $error='Member account नहीं मिला।'; $otpMode=false; }
                else { unset($_SESSION['whatsapp_otp_user_id'],$_SESSION['whatsapp_otp_username']); session_regenerate_id(true); unset($r['password_hash']); $_SESSION['user']=$r; $_SESSION['login_time']=date('Y-m-d H:i:s'); $_SESSION['last_activity']=time(); $_SESSION['csrf']=bin2hex(random_bytes(32)); persistRememberedLogin(); redirect('member-dashboard'); }
            } else $error=$msg;
        } elseif($action==='resend_otp' && $pendingUserId>0){
            $st=$db->prepare("SELECT u.id,u.display_name,m.name,m.mobile FROM users u LEFT JOIN members m ON m.id=u.member_id WHERE u.id=? AND u.role='member' LIMIT 1"); $st->bindValue(1,$pendingUserId,SQLITE3_INTEGER); $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
            if(!$r){$error='Member account नहीं मिला।';$otpMode=false;}
            else {[$ok,$msg]=createWhatsAppLoginOtp((int)$r['id'],(string)$r['mobile'],(string)($r['name']?:$r['display_name']));$error=$msg;$otpMode=true;}
        } else {
            $un=trim($_POST['username']??''); $pw=$_POST['password']??'';
            $st=$db->prepare("SELECT * FROM users WHERE username=?"); $st->bindValue(1,$un); $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
            $ipHash=hash('sha256',(string)($_SERVER['REMOTE_ADDR']??'unknown')); $window=time()-600;
            $lockCount=(int)$db->querySingle("SELECT COUNT(*) FROM login_attempts WHERE username='".SQLite3::escapeString($un)."' AND ip_hash='".SQLite3::escapeString($ipHash)."' AND success=0 AND attempted_at>$window");
            if($lockCount>=5){ http_response_code(403); $error='Too many failed login attempts. Please try again after 10 minutes.'; }
            elseif($r && password_verify($pw,$r['password_hash']) && ($loginPortal==='all' || ($loginPortal==='member' && $r['role']==='member') || ($loginPortal==='admin' && in_array($r['role'],['admin','staff'],true)))) {
                $_SESSION['remember_login']=isset($_POST['remember_login']);
                $stLog=$db->prepare('INSERT INTO login_attempts(username,ip_hash,attempted_at,success) VALUES(?,?,?,1)');$stLog->bindValue(1,$un);$stLog->bindValue(2,$ipHash);$stLog->bindValue(3,time());$stLog->execute();
                $db->exec("DELETE FROM login_attempts WHERE username='".SQLite3::escapeString($un)."' AND ip_hash='".SQLite3::escapeString($ipHash)."' AND success=0");
                $db->exec('DELETE FROM login_attempts WHERE attempted_at < '.(time()-86400));
                if($r['role']==='member'){
                    if(getSetting('member_whatsapp_otp_enabled','1')!=='1'){
                        session_regenerate_id(true); unset($r['password_hash']); $_SESSION['user']=$r; $_SESSION['login_time']=date('Y-m-d H:i:s'); $_SESSION['last_activity']=time(); $_SESSION['csrf']=bin2hex(random_bytes(32)); persistRememberedLogin(); redirect('member-dashboard');
                    }
                    $mid=(int)($r['member_id']??0); $ms=$db->prepare('SELECT name,mobile,status FROM members WHERE id=? LIMIT 1');$ms->bindValue(1,$mid,SQLITE3_INTEGER);$m=$ms->execute()->fetchArray(SQLITE3_ASSOC);
                    if(!$m || trim((string)$m['mobile'])===''){ $error='इस Member के लिए WhatsApp/mobile number उपलब्ध नहीं है। Admin से mobile number update कराएँ.'; }
                    elseif(strtolower((string)$m['status'])!=='active'){ $error='यह Member account active नहीं है।'; }
                    else { [$ok,$msg]=createWhatsAppLoginOtp((int)$r['id'],(string)$m['mobile'],(string)$m['name']); if($ok){$_SESSION['whatsapp_otp_user_id']=(int)$r['id'];$_SESSION['whatsapp_otp_username']=$un;$otpMode=true;$error=$msg;}else{$error=$msg;} }
                } else {
                    session_regenerate_id(true); unset($r['password_hash']); $_SESSION['user']=$r; $_SESSION['login_time']=date('Y-m-d H:i:s'); $_SESSION['last_activity']=time(); $_SESSION['csrf']=bin2hex(random_bytes(32)); persistRememberedLogin(); redirect('dashboard');
                }
            } else {
                $stLog=$db->prepare('INSERT INTO login_attempts(username,ip_hash,attempted_at,success) VALUES(?,?,?,0)');$stLog->bindValue(1,$un);$stLog->bindValue(2,$ipHash);$stLog->bindValue(3,time());$stLog->execute(); $error='Invalid username or password';
            }
        }
    }
    $loginBrandAsset=brandingAssetSetting('header_logo','assets/logo.png');
    if($loginBrandAsset==='assets/logo.png') $loginBrandAsset='assets/gs-mark.png';
    // Login-screen ticker: managed notices, the dashboard text notice, and recent activity.
    $loginNotices=[];
    if(getSetting('notice_enabled','1')==='1'){
        $loginNotices=noticeFeed();
        $staticLoginNotice=trim(getSetting('notice_text',''));
        if($staticLoginNotice!=='') array_unshift($loginNotices,['text'=>'📢 '.$staticLoginNotice]);
    }
    ob_start(); ?>
    <div class="login-wrap">
      <div class="login-mobile-masthead"><img src="<?=h($loginBrandAsset)?>" alt="GS Suraha logo"><div><b><?=h(getSetting('site_name',getSetting('society_name','GS SURAHA SAHYOG SAMITI')))?></b><small>SECURE FINANCE PORTAL</small></div></div>
      <?php if($loginNotices): ?><section class="login-notice-bar" aria-label="समिति की नवीनतम सूचना"><span class="login-notice-icon">◖))</span><b class="login-notice-label">महत्वपूर्ण सूचना</b><div class="login-notice-window"><div class="login-notice-track"><?php foreach($loginNotices as $ln): ?><span class="login-notice-item"><?=h((string)($ln['text']??''))?></span><?php endforeach; ?><?php foreach($loginNotices as $ln): ?><span class="login-notice-item" aria-hidden="true"><?=h((string)($ln['text']??''))?></span><?php endforeach; ?></div></div></section><?php endif; ?><section class="login-showcase">
        <img src="<?=h($loginBrandAsset)?>" alt="GS Suraha" class="login-showcase-logo">
        <div class="login-showcase-brand">GS SURAHA SAHYOG SAMITI</div>
        <div class="login-showcase-eyebrow">SECURE FINANCE PORTAL</div>
        <div class="login-hindi-motto"><span>सहयोग का विश्वास,</span><b>समिति का साथ</b><i></i></div>
        <div class="login-trust-grid login-trust-grid-4">
          <div><b>🤝</b><span>Together<small>Stronger</small></span></div>
          <div><b>🛡️</b><span>Secure<small>Transactions</small></span></div>
          <div><b>📈</b><span>Financial<small>Growth</small></span></div>
          <div><b>👥</b><span>Our<small>Community</small></span></div>
        </div>
      </section><div class="login-card">
      <div class="login-brand"><img class="login-logo" src="<?=h($loginBrandAsset)?>" alt="GS Suraha"><span>GS SURAHA SAHYOG SAMITI</span></div>
      <div class="eyebrow">SECURE FINANCE PORTAL</div>
      <?php if($otpMode): ?>
        <h1>WhatsApp OTP</h1><p class="login-subtitle">OTP भेजने से पहले, अगर 24 घंटे की WhatsApp विंडो बंद है तो नीचे बटन दबाकर 8877775963 पर Hi भेजें। फिर वापस आकर Resend OTP दबाएँ।</p>
        <?php if($error): ?><div class="alert <?=strpos($error,'भेज')!==false||strpos($error,'verified')!==false?'success':'danger'?>"><?=h($error)?></div><?php endif; ?>
        <form method="post" autocomplete="one-time-code"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="verify_otp">
          <label>OTP / ओटीपी</label><div class="login-input"><span>🔐</span><input name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="Enter 6-digit OTP"></div>
          <button class="btn primary full login-submit">Verify OTP <span>→</span></button>
        </form>
        <a class="btn full" style="margin-top:10px;display:flex;align-items:center;justify-content:center;gap:8px;background:#25D366;color:#fff;border-color:#25D366;text-decoration:none" href="https://wa.me/918877775963?text=Hi" target="_blank" rel="noopener noreferrer">🟢 WhatsApp पर Hi भेजें</a>
        <form method="post" style="margin-top:10px"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="resend_otp"><button class="btn full" type="submit">↻ Hi भेजने के बाद Resend OTP करें</button></form>
        <div class="login-secure">📱 OTP भेजने की कोशिश की गई · API स्वीकार करना डिलीवरी की गारंटी नहीं है · OTP 5 मिनट तक मान्य</div>
      <?php else: ?>
        <h1><?= $loginPortal==='member' ? 'Member Login' : ($loginPortal==='admin' ? 'Admin / Staff Login' : 'Welcome Back') ?></h1><p class="login-subtitle"><?= $loginPortal==='member' ? 'Members: login to access your account securely.' : ($loginPortal==='admin' ? 'Authorized Admin and Staff login only.' : 'Login to access your account securely.') ?></p>
        <?php if($error): ?><div class="alert danger"><?=h($error)?></div><?php endif; ?>
        <form method="post" autocomplete="on"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="login">
          <label>Login ID / Username</label><div class="login-input"><span>👤</span><input name="username" autocomplete="username" required placeholder="Enter Login ID or Username"></div>
          <label>Password</label><div class="login-input"><span>🔒</span><input id="loginPassword" type="password" name="password" autocomplete="current-password" required placeholder="Enter password"><button type="button" class="password-toggle" aria-label="Show password" aria-controls="loginPassword" aria-pressed="false" title="Show password" onclick="toggleLoginPassword()">Show password</button></div>
          <label class="remember-login"><input type="checkbox" name="remember_login" value="1"> Keep me logged in on this device for 30 days</label>
          <button type="submit" class="btn primary full login-submit">Login <span>→</span></button>
        </form>
        <script>function toggleLoginPassword(){var input=document.getElementById('loginPassword');var button=document.querySelector('.password-toggle');if(!input)return;var show=input.type==='password';input.type=show?'text':'password';if(button){button.textContent=show?'Hide password':'Show password';button.setAttribute('aria-label',show?'Hide password':'Show password');button.setAttribute('title',show?'Hide password':'Show password');button.setAttribute('aria-pressed',show?'true':'false');}}</script>
        <a href="?route=home" style="display:block;text-align:center;margin-top:12px;color:#08783e;text-decoration:none;font-weight:700">← Back to Home</a>
        <?php if($otpLoginEnabled): ?>
          <a class="btn full" style="margin-top:12px;display:flex;align-items:center;justify-content:center;gap:8px;background:#25D366;color:#fff;border-color:#25D366;text-decoration:none" href="https://wa.me/918877775963?text=Hi" target="_blank" rel="noopener noreferrer">🟢 WhatsApp पर Hi भेजें और OTP प्राप्त करें</a>
          <div class="login-secure">WhatsApp नंबर: 8877775963 · ग्राहक चैट में Hi भेजने के बाद वापस आकर लॉगिन करें।</div>
          <div class="login-secure">🔐 Secure login · Login ID और Password डालकर Login दबाएँ</div>
        <?php endif; ?>
      <?php endif; ?>
    </div><div class="login-screen-footer">— &nbsp; TOGETHER FOR A STRONGER TOMORROW &nbsp; —</div></div>
    <?php $c=ob_get_clean(); layout('Login',$c); exit;
}
if($route==='logout'){ $logoutNext=(string)($_GET['next']??'home'); if(!in_array($logoutNext,['home','member-login','admin-login'],true)) $logoutNext='home'; $_SESSION=[]; if(ini_get('session.use_cookies')){ $cp=session_get_cookie_params(); setcookie(session_name(),'',['expires'=>time()-42000,'path'=>$cp['path'],'secure'=>$cp['secure'],'httponly'=>$cp['httponly'],'samesite'=>$cp['samesite']??'Lax']); } session_destroy(); redirect($logoutNext); }

if($route==='maintenance'){
    ob_start(); ?><div class="panel" style="max-width:720px;margin:60px auto;text-align:center"><div style="font-size:56px">🔧</div><h1>Site Maintenance</h1><p class="muted">Website is temporarily under maintenance. Please try again later.</p><p class="hi-sub">वेबसाइट अभी रखरखाव में है। कृपया थोड़ी देर बाद पुनः प्रयास करें।</p></div><?php $c=ob_get_clean(); layout('Maintenance',$c); exit;
}

if($route==='notice-action'){
    requireRole(['admin','staff']);
    if($_SERVER['REQUEST_METHOD']!=='POST'){ redirect('dashboard'); }
    checkCsrf();
    $returnTo=(string)($_GET['return']??'dashboard');
    if(!in_array($returnTo,['dashboard','settings','control-center'],true)) $returnTo='dashboard';
    $returnUrl=$returnTo==='control-center'?'?route=control-center&tab=notice':'?route='.urlencode($returnTo);
    $action=(string)($_POST['action']??'');
    $id=(int)($_POST['id']??0);
    if($action==='delete_notice' && $id>0){
        $st=$db->prepare('DELETE FROM notices WHERE id=?');
        $st->bindValue(1,$id,SQLITE3_INTEGER); $st->execute();
        audit('notice_deleted','Notice ID '.$id);
        header('Location: '.$returnUrl); exit;
    }
    if($action==='clear_static_notice'){
        $st=$db->prepare("INSERT INTO settings(key,value) VALUES('notice_text','') ON CONFLICT(key) DO UPDATE SET value=''");
        $st->execute(); audit('notice_text_deleted','Dashboard static notice deleted'); header('Location: '.$returnUrl); exit;
    }
    if($action==='toggle_notice' && $id>0){
        $st=$db->prepare('UPDATE notices SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?');
        $st->bindValue(1,$id,SQLITE3_INTEGER); $st->execute(); audit('notice_toggled','Notice ID '.$id); header('Location: '.$returnUrl); exit;
    }
    if($action==='edit_notice' && $id>0){
        $title=trim((string)($_POST['title']??'')); $body=trim((string)($_POST['body']??''));
        if($body!==''){ $st=$db->prepare('UPDATE notices SET title=?,body=? WHERE id=?'); $st->bindValue(1,$title,SQLITE3_TEXT); $st->bindValue(2,$body,SQLITE3_TEXT); $st->bindValue(3,$id,SQLITE3_INTEGER); $st->execute(); audit('notice_updated','Notice ID '.$id); }
        header('Location: '.$returnUrl); exit;
    }
    header('Location: '.$returnUrl); exit;
}

if($route==='control-center'){
    requireRole(['admin']); if(!isSuperAdmin()) { http_response_code(403); exit('Super Admin permission required'); }
    $tab=(string)($_GET['tab']??'home'); if($tab==='overview')$tab='home'; $msg=''; $err='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=$_POST['action']??'';
        if($action==='delete_activity_notice'){
            $noticeKey=trim((string)($_POST['notice_key']??''));
            if($noticeKey!==''){
                // Normalize legacy URL|ID|title keys so a changed title/status cannot resurrect a loan notice.
                if(preg_match('/(?:route=loan-applications(?:&focus=|\|)|loan\|)(\d+)/',$noticeKey,$mm)){
                    $noticeKey='loan|'.(int)$mm[1];
                } elseif(preg_match('/(?:route=contributions(?:&focus=|\|)|contribution\|)(\d+)/',$noticeKey,$mm)){
                    // Normalize legacy URL/title-based keys to the same stable key used by noticeFeed().
                    $noticeKey='contribution|'.(int)$mm[1];
                }
                $dismiss=$db->prepare("INSERT OR IGNORE INTO activity_notice_dismissals(user_id,notice_key) VALUES(?,?)");
                $dismiss->bindValue(1,(int)user()['id'],SQLITE3_INTEGER);
                $dismiss->bindValue(2,$noticeKey,SQLITE3_TEXT);
                $dismiss->execute();
                audit('activity_notice_deleted',$noticeKey);
            }
            header('Location: ?route=control-center&tab=notice'); exit;
        }
        if($action==='save_frontpage'){
            $frontTextKeys=['site_name','society_tagline','front_hero_title','front_hero_slogan','front_hero_title_color','front_hero_slogan_color','front_login_heading_color','front_member_login_color','front_admin_login_color','front_hero_side','front_login_heading','front_member_login_label','front_admin_login_label','front_feature_heading','front_hero_promise_1','front_hero_promise_2','front_hero_promise_3','front_feature_1','front_feature_2','front_feature_3','front_feature_4','front_nav_home','front_nav_members','front_nav_reports','front_nav_notices','front_members_title','front_members_link_text','front_notice_title','front_latest_contribution_title','front_latest_contribution_template','front_latest_contribution_empty','front_about_title','front_about_body','front_contact_title','front_contribution_heading','front_contribution_body','front_contribution_button','front_footer_about_label','front_footer_contact_label','front_header_bg_color','front_header_text_color','front_header_accent_color','front_header_image_fit','front_banner_position','front_banner_overlay','contact_phone','contact_email','contact_address'];
            foreach($frontTextKeys as $fk){
                if(!array_key_exists($fk,$_POST)) continue;
                $fv=trim((string)$_POST[$fk]);
                if(strlen($fv)>12000) $fv=substr($fv,0,12000);
                if($fk==='front_hero_side' && !in_array($fv,['right','left'],true)) $fv='right';
                if($fk==='front_banner_position' && !in_array($fv,['left','center','right'],true)) $fv='center';
                if($fk==='front_header_image_fit' && !in_array($fv,['contain','cover','auto'],true)) $fv='cover';
                if($fk==='front_banner_overlay' && !in_array($fv,['light','green','blue','none'],true)) $fv='light';
                if(in_array($fk,['front_header_bg_color','front_header_text_color','front_header_accent_color','front_hero_title_color','front_hero_slogan_color','front_login_heading_color','front_member_login_color','front_admin_login_color'],true)) { if(!preg_match('/^#[0-9a-fA-F]{6}$/',$fv)) continue; $fv=strtoupper($fv); }
                if($fk==='site_name' && $fv==='') continue;
                $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$fk,SQLITE3_TEXT); $st->bindValue(2,$fv,SQLITE3_TEXT); $st->execute();
                if($fk==='site_name'){ $st=$db->prepare("INSERT INTO settings(key,value) VALUES('society_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$fv,SQLITE3_TEXT); $st->execute(); }
            }
            $frontSwitches=['front_header_artwork_only','front_header_bg_transparent','front_show_nav','front_show_nav_home','front_show_nav_members','front_show_nav_reports','front_show_nav_notices','front_show_hero','front_show_login','front_show_members','front_show_notices','front_show_latest_contribution','front_show_about','front_show_contribution','front_show_features'];
            foreach($frontSwitches as $fk){ if(!array_key_exists($fk,$_POST)) continue; $fv=((string)$_POST[$fk]==='1')?'1':'0'; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$fk,SQLITE3_TEXT); $st->bindValue(2,$fv,SQLITE3_TEXT); $st->execute(); }
            $frontSizeLimits=['front_header_height'=>[48,180,76],'front_logo_size'=>[28,130,72],'front_nav_font_size'=>[8,22,12],'front_nav_item_padding'=>[2,16,7],'front_brand_name_size'=>[12,48,28],'front_brand_tagline_size'=>[8,24,17]];
            foreach($frontSizeLimits as $fk=>$limits){ if(!array_key_exists($fk,$_POST)) continue; $fv=max($limits[0],min($limits[1],(int)$_POST[$fk])); $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$fk,SQLITE3_TEXT); $st->bindValue(2,(string)$fv,SQLITE3_TEXT); $st->execute(); }
            if(isset($_FILES['front_hero_image']) && is_array($_FILES['front_hero_image']) && ($_FILES['front_hero_image']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE){
                $ff=$_FILES['front_hero_image']; $mime=(new finfo(FILEINFO_MIME_TYPE))->file((string)$ff['tmp_name']); $allowed=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'];
                if(($ff['error']??UPLOAD_ERR_OK)!==UPLOAD_ERR_OK || (int)($ff['size']??0)>5*1024*1024 || !isset($allowed[$mime])) $err='Hero photo must be JPG, PNG or WebP up to 5 MB.';
                else { $name='front_hero_'.date('Ymd_His').'_'.bin2hex(random_bytes(4)).'.'.$allowed[$mime]; $dest=__DIR__.'/uploads/branding/'.$name; if(move_uploaded_file((string)$ff['tmp_name'],$dest)){ deleteBrandingAsset('front_hero_image',''); setSetting('front_hero_image','uploads/branding/'.$name); } else $err='Hero photo upload failed.'; }
            }
            if(isset($_FILES['front_header_image']) && is_array($_FILES['front_header_image']) && ($_FILES['front_header_image']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE){
                $ff=$_FILES['front_header_image']; $tmp=(string)($ff['tmp_name']??''); $mime=($ff['error']??UPLOAD_ERR_OK)===UPLOAD_ERR_OK && is_file($tmp)?(new finfo(FILEINFO_MIME_TYPE))->file($tmp):''; $allowed=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp']; $dimensions=$tmp!==''?@getimagesize($tmp):false;
                if(($ff['error']??UPLOAD_ERR_OK)!==UPLOAD_ERR_OK || (int)($ff['size']??0)>5*1024*1024 || !isset($allowed[$mime]) || !$dimensions || $dimensions[0]<1 || $dimensions[1]<1 || $dimensions[0]>10000 || $dimensions[1]>10000) $err='Header artwork must be a valid JPG, PNG or WebP image up to 5 MB and 10000 × 10000 pixels.';
                else { $name='front_header_'.date('Ymd_His').'_'.bin2hex(random_bytes(4)).'.'.$allowed[$mime]; $dest=__DIR__.'/uploads/branding/'.$name; if(move_uploaded_file($tmp,$dest)){ deleteBrandingAsset('front_header_image',''); setSetting('front_header_image','uploads/branding/'.$name); } else $err='Header artwork upload failed.'; }
            }
            if($err==='') { audit('frontpage_updated','Public front page text updated'); $msg='Front Page settings saved successfully.'; }
        } elseif($action==='save_control_settings'){
            $keys=['site_name','society_tagline','contact_phone','contact_email','contact_address','primary_color','accent_color','notice_enabled','notice_move','notice_speed','mobile_lock','loan_interest_rate','loan_default_tenure','loan_penalty_rate','loan_eligibility_percent','monthly_contribution','member_interest_pool','session_timeout_minutes','maintenance_mode','footer_text','terms_text','privacy_text','menu_members','menu_loans','menu_payments','menu_reports','menu_notifications','doc_summary_title','doc_summary_subtitle','doc_affidavit_title','doc_affidavit_subtitle','doc_agreement_title','doc_agreement_subtitle','idcard_primary','idcard_secondary','idcard_text','idcard_back_text','idcard_footer','idcard_border_radius','idcard_show_mobile','idcard_show_status','idcard_show_father','idcard_show_address','idcard_show_qr','idcard_show_signatures','idcard_show_photo','slip_primary','slip_secondary','slip_text','slip_footer','slip_border_radius','slip_show_logo','slip_show_member','slip_show_date','slip_show_mode','slip_show_reference','slip_show_status','slip_show_note','slip_title_hi','slip_title_en'];
            foreach($keys as $k){ if(!array_key_exists($k,$_POST)) continue; $v=trim((string)$_POST[$k]); if($k==='notice_enabled'||$k==='notice_move'||$k==='mobile_lock'||$k==='maintenance_mode'||str_starts_with($k,'menu_')) $v=($v==='1'?'1':'0'); if($k==='site_name'){ $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,'site_name'); $st->bindValue(2,$v); $st->execute(); $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,'society_name'); $st->bindValue(2,$v); $st->execute(); continue; } $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k); $st->bindValue(2,$v); $st->execute(); }
            audit('control_settings_updated','A2Z Control Center settings updated'); $msg='Settings saved successfully.';
        } elseif($action==='add_notice'){
            foreach(['notice_speed','notice_move','notice_enabled'] as $nk){ $nv=trim((string)($_POST[$nk]??getSetting($nk,$nk==='notice_move'?'1':'1'))); if($nk==='notice_move'||$nk==='notice_enabled') $nv=$nv==='1'?'1':'0'; if($nk==='notice_speed') $nv=(string)max(5,min(180,(int)$nv)); $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$nk); $st->bindValue(2,$nv); $st->execute(); }
            $body=trim((string)($_POST['body']??'')); $title=trim((string)($_POST['title']??'')); if($body==='') $err='Notice text required.'; else { $st=$db->prepare("INSERT INTO notices(title,body,enabled,created_by) VALUES(?,?,1,?)"); $st->bindValue(1,$title); $st->bindValue(2,$body); $st->bindValue(3,(int)user()['id'],SQLITE3_INTEGER); $st->execute(); audit('notice_created',$title.' | '.$body); header('Location: ?route=control-center&tab=notice&notice_added=1'); exit; }
        } elseif($action==='edit_notice'){ $id=(int)($_POST['id']??0); $title=trim((string)($_POST['title']??'')); $body=trim((string)($_POST['body']??'')); if($id<=0||$body===''){$msg='Notice title/text required.';$msgType='danger';}else{$st=$db->prepare("UPDATE notices SET title=?,body=? WHERE id=?");$st->bindValue(1,$title);$st->bindValue(2,$body);$st->bindValue(3,$id,SQLITE3_INTEGER);$st->execute();audit('notice_updated','Notice ID '.$id);$msg='Notice updated.';}
        } elseif($action==='clear_static_notice'){ $st=$db->prepare("INSERT INTO settings(key,value) VALUES('notice_text','') ON CONFLICT(key) DO UPDATE SET value=''");$st->execute();audit('notice_text_deleted','Dashboard static notice deleted');header('Location: ?route=control-center&tab=notice'); exit;
        } elseif($action==='delete_notice'){ $id=(int)($_POST['id']??0); $st=$db->prepare("DELETE FROM notices WHERE id=?"); $st->bindValue(1,$id,SQLITE3_INTEGER); $st->execute(); audit('notice_deleted','Notice ID '.$id); header('Location: ?route=control-center&tab=notice'); exit;
        } elseif($action==='toggle_notice'){ $id=(int)($_POST['id']??0); $st=$db->prepare("UPDATE notices SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?"); $st->bindValue(1,$id,SQLITE3_INTEGER); $st->execute(); audit('notice_toggled','Notice ID '.$id); header('Location: ?route=control-center&tab=notice'); exit;
        } elseif($action==='delete_branding'){
            $field=(string)($_POST['brand_field']??''); $map=['logo'=>['header_logo','assets/logo.png'],'banner'=>['header_banner',''],'favicon'=>['site_favicon','']];
            if(!isset($map[$field])) { $err='Unknown branding asset.'; }
            else { deleteBrandingAsset($map[$field][0],$map[$field][1]); audit('branding_deleted',$field); $msg=ucfirst($field).' reset safely to default.'; }
        } elseif($action==='upload_branding'){
            $field=(string)($_POST['brand_field']??''); $map=['logo'=>'header_logo','banner'=>'header_banner','favicon'=>'site_favicon']; $key=$map[$field]??''; $f=$_FILES['branding_file']??null;
            if($key===''||!$f||$f['error']!==UPLOAD_ERR_OK) $err='Please select a valid image file.'; else { $mime=(new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']); $allowed=['image/png'=>'png','image/jpeg'=>'jpg','image/webp'=>'webp','image/x-icon'=>'ico','image/vnd.microsoft.icon'=>'ico']; if(!isset($allowed[$mime]) || $f['size']>3*1024*1024) $err='Only PNG/JPG/WEBP/ICO images up to 3MB are allowed.'; else { $dir=__DIR__.'/uploads/branding'; if(!is_dir($dir)) mkdir($dir,0775,true); $name=$field.'_'.bin2hex(random_bytes(6)).'.'.$allowed[$mime]; $dest=$dir.'/'.$name; if(move_uploaded_file($f['tmp_name'],$dest)){ $rel='uploads/branding/'.$name; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$key); $st->bindValue(2,$rel); $st->execute(); audit('branding_updated',$field.' => '.$rel); $msg=ucfirst($field).' updated.'; } else $err='Upload failed.'; } }
        } elseif($action==='save_idcard_design'){
            $keys=['idcard_primary','idcard_secondary','idcard_text','idcard_back_text','idcard_footer','idcard_border_radius','idcard_show_mobile','idcard_show_status','idcard_show_father','idcard_show_address','idcard_show_qr','idcard_show_signatures','idcard_show_photo'];
            foreach($keys as $k){ $v=trim((string)($_POST[$k]??'')); if(str_starts_with($k,'idcard_show_')) $v=($v==='1'?'1':'0'); if($k==='idcard_border_radius'){ $v=(string)max(0,min(30,(int)$v)); } $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k); $st->bindValue(2,$v); $st->execute(); }
            audit('idcard_design_updated','Member ID Card design updated'); $msg='ID Card design saved successfully.';
        } elseif($action==='save_payment_system') {
            $keys=['monthly_contribution','member_interest_pool','loan_eligibility_percent','upi_id','upi_name','payment_api_url','payment_api_key','payment_api_secret','payment_api_enabled','payment_auto_verify','payment_allow_member_upi','payment_allow_qr','payment_allow_api','payment_require_reference','payment_slip_enabled','payment_send_slip_admin','payment_send_slip_staff','loan_payout_provider','loan_payout_mode','loan_payout_api_url','loan_payout_api_key','loan_payout_api_secret','loan_payout_account_id','loan_payout_webhook_secret','loan_payout_enabled'];
            foreach($keys as $k){ $v=trim((string)($_POST[$k]??'')); if(in_array($k,['payment_api_enabled','payment_auto_verify','payment_allow_member_upi','payment_allow_qr','payment_allow_api','payment_require_reference','payment_slip_enabled','payment_send_slip_admin','payment_send_slip_staff','loan_payout_enabled'],true)) $v=($v==='1'?'1':'0'); $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k); $st->bindValue(2,$v); $st->execute(); }
            audit('payment_system_updated','Payment System settings updated from A2Z Control Center'); $msg='Payment System settings saved successfully.';
        } elseif($action==='save_slip_design') {
            $keys=['slip_primary','slip_secondary','slip_text','slip_footer','slip_border_radius','slip_show_logo','slip_show_member','slip_show_date','slip_show_mode','slip_show_reference','slip_show_status','slip_show_note','slip_title_hi','slip_title_en'];
            foreach($keys as $k){ $v=trim((string)($_POST[$k]??'')); if(str_starts_with($k,'slip_show_')) $v=($v==='1'?'1':'0'); if($k==='slip_border_radius') $v=(string)max(0,min(30,(int)$v)); $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k); $st->bindValue(2,$v); $st->execute(); }
            audit('slip_design_updated','Payment slip design updated'); $msg='Slip design saved successfully.';
        } elseif($action==='reset_design') {
            $type=(string)($_POST['design_type']??'');
            $defaults=[
                'idcard'=>['idcard_primary'=>'#0b65d5','idcard_secondary'=>'#06265b','idcard_text'=>'#17324d','idcard_back_text'=>'#4e6076','idcard_footer'=>'सहयोग से समृद्धि','idcard_border_radius'=>'12','idcard_show_mobile'=>'1','idcard_show_status'=>'1','idcard_show_father'=>'1','idcard_show_address'=>'1','idcard_show_qr'=>'1','idcard_show_signatures'=>'1','idcard_show_photo'=>'1'],
                'slip'=>['slip_primary'=>'#0b65d5','slip_secondary'=>'#06265b','slip_text'=>'#17324d','slip_footer'=>'धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।','slip_border_radius'=>'12','slip_show_logo'=>'1','slip_show_member'=>'1','slip_show_date'=>'1','slip_show_mode'=>'1','slip_show_reference'=>'1','slip_show_status'=>'1','slip_show_note'=>'1','slip_title_hi'=>'भुगतान रसीद','slip_title_en'=>'PAYMENT RECEIPT'],
                'summary'=>['doc_summary_title'=>'EMI Loan Summary','doc_summary_subtitle'=>'ईएमआई ऋण सारांश'],
                'affidavit'=>['doc_affidavit_title'=>'AFFIDAVIT','doc_affidavit_subtitle'=>'शपथ-पत्र'],
                'agreement'=>['doc_agreement_title'=>'Loan Agreement','doc_agreement_subtitle'=>'ऋण समझौता'],
            ];
            if(!isset($defaults[$type])) $err='Invalid design type.'; else {
                foreach($defaults[$type] as $k=>$v){ $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k); $st->bindValue(2,$v); $st->execute(); }
                audit('design_reset',$type.' design restored to default'); $msg=ucfirst($type).' design restored to original/default design.';
            }
        } elseif($action==='restore_db'){
            $f=$_FILES['restore_file']??null; if(!$f||$f['error']!==UPLOAD_ERR_OK) $err='Please select a backup file.'; else { $head=file_get_contents($f['tmp_name'],false,null,0,16); if($head!==("SQLite format 3".chr(0))) $err='Invalid SQLite backup file.'; else { $backup=__DIR__.'/data/pre_restore_'.date('Ymd_His').'.sqlite'; if(!copy(DB_FILE,$backup)) $err='Could not create safety backup.'; elseif(!copy($f['tmp_name'],DB_FILE)) $err='Restore failed.'; else { audit('database_restored','Database restored from uploaded backup'); $msg='Database restored. Please log in again if your session ended.'; } } }
        }
    }
    $settingsKeys=['site_name'=>'GS Suraha Finance','app_download_url'=>'','society_tagline'=>'Finance Co-operative Society','contact_phone'=>'','contact_email'=>'','contact_address'=>'','primary_color'=>'','accent_color'=>'','notice_enabled'=>'1','notice_move'=>'1','notice_speed'=>'35','mobile_lock'=>'1','loan_interest_rate'=>'','loan_default_tenure'=>'12','loan_penalty_rate'=>'','loan_eligibility_percent'=>'80','monthly_contribution'=>'0','member_interest_pool'=>'0','session_timeout_minutes'=>'60','maintenance_mode'=>'0','footer_text'=>'','terms_text'=>'','privacy_text'=>'','menu_members'=>'1','menu_loans'=>'1','menu_payments'=>'1','menu_reports'=>'1','menu_notifications'=>'1','idcard_primary'=>'#0b65d5','idcard_secondary'=>'#06265b','idcard_text'=>'#17324d','idcard_back_text'=>'#4e6076','idcard_footer'=>'सहयोग से समृद्धि','idcard_border_radius'=>'12','idcard_show_mobile'=>'1','idcard_show_status'=>'1','idcard_show_father'=>'1','idcard_show_address'=>'1','idcard_show_qr'=>'1','idcard_show_signatures'=>'1','idcard_show_photo'=>'1','slip_primary'=>'#0b65d5','slip_secondary'=>'#06265b','slip_text'=>'#17324d','slip_footer'=>'धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।','slip_border_radius'=>'12','slip_show_logo'=>'1','slip_show_member'=>'1','slip_show_date'=>'1','slip_show_mode'=>'1','slip_show_reference'=>'1','slip_show_status'=>'1','slip_show_note'=>'1','slip_title_hi'=>'भुगतान रसीद','slip_title_en'=>'PAYMENT RECEIPT','doc_summary_title'=>'EMI Loan Summary','doc_summary_subtitle'=>'ईएमआई ऋण सारांश','doc_affidavit_title'=>'AFFIDAVIT','doc_affidavit_subtitle'=>'शपथ-पत्र','doc_agreement_title'=>'Loan Agreement','doc_agreement_subtitle'=>'ऋण समझौता'];
    $notices=$db->query("SELECT id,title,body,enabled,created_at FROM notices ORDER BY id DESC LIMIT 30");
    $auditRows=$db->query("SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100");
    $caps=['dashboard'=>'Dashboard','members'=>'Members','contributions'=>'Contributions','loans'=>'Loans','payments'=>'Payments','reports'=>'Reports','reminders'=>'Reminders','settings'=>'Settings','communications'=>'WhatsApp / SMS','funds'=>'Expenses / Withdrawals','backup'=>'Backup','notifications'=>'Notifications','users'=>'Staff / Member IDs'];
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">SUPER ADMIN</div><h1>⚙️ A2Z Control Center</h1><p>Site की सामान्य settings और controls यहीं से manage करें।</p></div><a class="btn" href="?route=admin-panel">← Admin Panel</a></div>
    <?php if($msg): ?><div class="alert success">✅ <?=h($msg)?></div><?php endif; ?><?php if($err): ?><div class="alert danger">⚠️ <?=h($err)?></div><?php endif; ?>
    <div class="panel a2z-tabs-panel">
      <div class="a2z-tabs">
      <?php foreach(['overview'=>'🏠 Settings Home','site'=>'⚙️ Society','frontpage'=>'🏠 Front Page','notice'=>'📢 Notices','branding'=>'🖼️ Branding','whatsapp'=>'💬 WhatsApp Center','payment'=>'💳 Payments','loan'=>'💰 Loan & EMI','security'=>'🔐 Security','menus'=>'🎨 Menus','idcard'=>'🪪 ID Card','slip'=>'🧾 Receipt','summary'=>'📊 Summary Doc','affidavit'=>'📄 Affidavit','agreement'=>'🤝 Agreement','legal'=>'📝 Legal','backup'=>'💾 Backup','audit'=>'🧾 Audit Log'] as $k=>$v): ?><a class="a2z-tab <?= $tab===$k?'active':'' ?>" href="<?= $k==='whatsapp' ? '?route=whatsapp-center' : '?route=control-center&tab='.$k ?>"><?=h($v)?></a><?php endforeach; ?>
      </div>
    </div>
    <?php if($tab==='overview'): ?>
    <style>
      .settings-hub-group{margin:18px 0 22px}.settings-hub-group h2{font-size:17px;margin:0 0 12px;color:#12305a}.settings-hub-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.settings-hub-card{display:flex;align-items:center;gap:12px;padding:15px;border:1px solid #e2eaf3;border-radius:15px;background:linear-gradient(145deg,#fff,#f7fbff);text-decoration:none;color:#17324d;box-shadow:0 5px 18px rgba(18,48,90,.05);min-height:76px}.settings-hub-card:hover{border-color:#21a36c;transform:translateY(-1px)}.settings-hub-icon{width:43px;height:43px;border-radius:13px;display:grid;place-items:center;background:#e4f6ed;font-size:22px;flex-shrink:0}.settings-hub-card b{display:block;font-size:14px}.settings-hub-card small{display:block;color:#64748b;margin-top:4px;line-height:1.35}@media(max-width:760px){.settings-hub-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-hub-card{padding:11px;gap:9px}.settings-hub-icon{width:36px;height:36px;font-size:18px}}@media(max-width:420px){.settings-hub-grid{grid-template-columns:1fr}}
    </style>
    <div class="panel"><div class="panel-head"><div><h2>⚙️ All Settings in One Place</h2><p class="muted">सभी settings को सही category में रखा गया है। किसी card पर दबाकर संबंधित setting खोलें।</p></div><span class="badge success">Centralized</span></div>
      <div class="settings-hub-group"><h2>🏢 Society & Website</h2><div class="settings-hub-grid">
        <a class="settings-hub-card" href="?route=control-center&tab=site"><span class="settings-hub-icon">🏢</span><span><b>Society Information</b><small>नाम, संपर्क, पता और रंग</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=frontpage"><span class="settings-hub-icon">🌐</span><span><b>Front Page</b><small>मुख्य पेज का text और banner</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=branding"><span class="settings-hub-icon">🖼️</span><span><b>Logo & Branding</b><small>Logo, favicon और banner</small></span></a><a class="settings-hub-card" href="?route=app-release-admin"><span class="settings-hub-icon">📱</span><span><b>Android App Release</b><small>APK, version और update prompt</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=notice"><span class="settings-hub-icon">📢</span><span><b>Notices</b><small>समिति की सूचनाएँ</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=menus"><span class="settings-hub-icon">🎨</span><span><b>Menu & Page Visibility</b><small>मेनू में क्या दिखे</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=legal"><span class="settings-hub-icon">📝</span><span><b>Legal Pages</b><small>Terms और privacy content</small></span></a>
      </div></div>
      <div class="settings-hub-group"><h2>💰 Savings, Loans & Payments</h2><div class="settings-hub-grid">
        <a class="settings-hub-card" href="?route=control-center&tab=payment"><span class="settings-hub-icon">💳</span><span><b>Payment System</b><small>Contribution, UPI और payment rules</small></span></a>
        <a class="settings-hub-card" href="?route=settings"><span class="settings-hub-icon">🧾</span><span><b>Contribution & UPI Setup</b><small>Monthly contribution, merchant UPI और gateway credentials</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=loan"><span class="settings-hub-icon">🏦</span><span><b>Loan & EMI Rules</b><small>Interest, tenure और eligibility</small></span></a>
        <a class="settings-hub-card" href="?route=fund-adjustments"><span class="settings-hub-icon">🧮</span><span><b>Expenses & Withdrawals</b><small>Fund adjustments</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=summary"><span class="settings-hub-icon">📊</span><span><b>Loan Summary Document</b><small>Document title और subtitle</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=slip"><span class="settings-hub-icon">🧾</span><span><b>Payment Receipt Design</b><small>रसीद का रंग, logo और text</small></span></a>
      </div></div>
      <div class="settings-hub-group"><h2>👥 Users & Communication</h2><div class="settings-hub-grid">
        <a class="settings-hub-card" href="?route=admin-users"><span class="settings-hub-icon">🛡️</span><span><b>Admin IDs & Permissions</b><small>Admin accounts और access</small></span></a>
        <a class="settings-hub-card" href="?route=staff-member-users"><span class="settings-hub-icon">👥</span><span><b>Staff & Member IDs</b><small>Login accounts manage करें</small></span></a>
        <a class="settings-hub-card" href="?route=staff-member-assignment"><span class="settings-hub-icon">🧑‍🤝‍🧑</span><span><b>Staff–Member Mapping</b><small>Staff को members assign करें</small></span></a>
        <a class="settings-hub-card" href="?route=account-settings"><span class="settings-hub-icon">🔑</span><span><b>Account & Password</b><small>अपने login credentials और account options</small></span></a>
        <a class="settings-hub-card" href="?route=whatsapp-sms-center"><span class="settings-hub-icon">💬</span><span><b>WhatsApp & SMS</b><small>Messaging providers और API</small></span></a>
        <a class="settings-hub-card" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1"><span class="settings-hub-icon">📨</span><span><b>WhatsApp Center</b><small>Bulk messages और chat logs</small></span></a>
        <a class="settings-hub-card" href="?route=notifications"><span class="settings-hub-icon">🔔</span><span><b>Notifications</b><small>System activity and alerts</small></span></a>
      </div></div>
      <div class="settings-hub-group"><h2>🔐 Security, Documents & Maintenance</h2><div class="settings-hub-grid">
        <a class="settings-hub-card" href="?route=control-center&tab=security"><span class="settings-hub-icon">🔐</span><span><b>Security Settings</b><small>Session timeout और maintenance</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=idcard"><span class="settings-hub-icon">🪪</span><span><b>Member ID Card</b><small>ID card design और fields</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=affidavit"><span class="settings-hub-icon">📄</span><span><b>Affidavit Design</b><small>शपथ-पत्र का format</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=agreement"><span class="settings-hub-icon">🤝</span><span><b>Loan Agreement</b><small>समझौते का format</small></span></a>
        <a class="settings-hub-card" href="?route=backup"><span class="settings-hub-icon">💾</span><span><b>Database Backup</b><small>Backup और restore</small></span></a>
        <a class="settings-hub-card" href="?route=control-center&tab=audit"><span class="settings-hub-icon">🧾</span><span><b>Audit Log</b><small>किसने क्या बदलाव किया</small></span></a>
      </div></div>
      <div class="alert info">सुरक्षा के लिए वित्तीय रिकॉर्ड, loan approval और verified payment को सामान्य settings से सीधे बदलने का विकल्प नहीं दिया गया है। Backup/Restore करने से पहले current database का अलग backup अवश्य रखें।</div>
    </div>
    <?php elseif($tab==='idcard'): ?>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><div><h2>🪪 ID Card Designer</h2><small class="muted">Member ID Card का design बिना code बदले बदलें।</small></div><span class="badge success">Live</span></div>
      <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_idcard_design">
        <label>Front Primary Color</label><input type="color" name="idcard_primary" value="<?=h(getSetting('idcard_primary','#0b65d5'))?>">
        <label>Front Secondary Color</label><input type="color" name="idcard_secondary" value="<?=h(getSetting('idcard_secondary','#06265b'))?>">
        <label>Text Color</label><input type="color" name="idcard_text" value="<?=h(getSetting('idcard_text','#17324d'))?>">
        <label>Back Text Color</label><input type="color" name="idcard_back_text" value="<?=h(getSetting('idcard_back_text','#4e6076'))?>">
        <label>Card Footer Text</label><input name="idcard_footer" value="<?=h(getSetting('idcard_footer','सहयोग से समृद्धि'))?>">
        <label>Border Radius (px)</label><input type="number" min="0" max="30" name="idcard_border_radius" value="<?=h(getSetting('idcard_border_radius','12'))?>">
        <div class="profile-grid" style="margin-top:12px">
          <?php foreach(['photo'=>'Photo / फोटो','father'=>'Father Name / पिता का नाम','mobile'=>'Mobile / मोबाइल','status'=>'Status / स्थिति','address'=>'Address / पता','qr'=>'QR Verification','signatures'=>'Signatures / हस्ताक्षर'] as $k=>$lab): $key='idcard_show_'.$k; ?>
          <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="<?=$key?>" value="1" <?=getSetting($key,'1')==='1'?'checked':''?>> <?=h($lab)?></label>
          <?php endforeach; ?>
        </div>
        <button class="btn primary full" style="margin-top:16px">💾 Save ID Card Design</button><div class="inline-form" style="margin-top:10px"><button type="submit" form="reset-idcard-form" class="btn danger" onclick="return confirm('ID Card का पुराना/default design वापस लाएँ?')">↩ Reset to Original</button></div>
      </form><form id="reset-idcard-form" method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="reset_design"><input type="hidden" name="design_type" value="idcard"></form></div>
      <div class="panel"><div class="panel-head"><h2>👀 Design Preview</h2><a class="btn small" target="_blank" href="?route=member-id-card&id=1">Open Sample Card</a></div>
        <div style="border:1px solid #dce4ef;border-radius:<?=h(getSetting('idcard_border_radius','12'))?>px;overflow:hidden;background:#fff;box-shadow:0 12px 30px rgba(15,23,42,.10)">
          <div style="padding:18px;background:linear-gradient(135deg,<?=h(getSetting('idcard_secondary','#06265b'))?>,<?=h(getSetting('idcard_primary','#0b65d5'))?>);color:#fff;display:flex;align-items:center;gap:12px"><img src="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>" style="width:50px;height:50px;object-fit:contain;background:#fff;border-radius:10px"><div><b style="font-size:17px">GS सुराहा सहयोग समिति</b><small style="display:block"><?=h(getSetting('society_tagline','Finance Co-operative Society'))?></small></div></div>
          <div style="padding:20px;color:<?=h(getSetting('idcard_text','#17324d'))?>"><b style="font-size:20px">MEMBER NAME</b><div style="margin-top:8px">Member ID: <b>GS0001</b></div><div style="margin-top:5px">Father Name / पिता का नाम</div><div style="margin-top:5px">Mobile / मोबाइल</div></div>
          <div style="padding:12px 18px;background:#f7f9fc;border-top:1px solid #e7ebf2"> <b><?=h(getSetting('idcard_footer','सहयोग से समृद्धि'))?></b></div>
        </div><div class="alert info" style="margin-top:14px">Design changes सभी नए और पुराने Member ID Cards पर लागू होंगे।</div>
      </div>
    </div>
    <?php elseif($tab==='frontpage'): ?>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><div><h2>🏠 Front Page Editor</h2><small class="muted">Homepage ke visible text, notices, sections, navigation aur visibility yahin se manage karein.</small></div><span class="badge success">Live</span></div>
      <form method="post" enctype="multipart/form-data" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_frontpage">
      <script>document.addEventListener('change',function(e){if(e.target&&e.target.id==='frontHeaderArtworkInput'&&e.target.files&&e.target.files[0]){var i=new Image(),f=e.target.files[0],label=document.getElementById('frontHeaderArtworkDimensions');i.onload=function(){label.textContent='Selected image: '+i.naturalWidth+' × '+i.naturalHeight+' px';URL.revokeObjectURL(i.src);};i.src=URL.createObjectURL(f);}});</script>
        <div class="span2"><h3>🏷️ Brand & Hero</h3></div>
        <div><label>Society / Brand Name</label><input name="site_name" value="<?=h(getSetting('site_name',getSetting('society_name','GS Suraha Sahyog Samiti')))?>"></div>
        <div><label>Top-bar Tagline</label><input name="society_tagline" value="<?=h(getSetting('society_tagline','Finance Co-operative Society'))?>"></div>
        <div class="span2"><label>Hero Heading</label><input name="front_hero_title" value="<?=h(getSetting('front_hero_title',getSetting('site_name',getSetting('society_name','GS Suraha Sahyog Samiti'))))?>"></div>
        <div class="span2"><label>Hero Slogan</label><textarea name="front_hero_slogan" rows="2" placeholder="“सदस्यों का विश्वास,
समिति का साथ”"><?=h(getSetting('front_hero_slogan','“सदस्यों का विश्वास,
समिति का साथ”'))?></textarea></div>
        <div><label>Login card side (slogan appears opposite, at top)</label><select name="front_hero_side"><option value="right" <?=getSetting('front_hero_side','right')==='right'?'selected':''?>>Right side (recommended)</option><option value="left" <?=getSetting('front_hero_side','right')==='left'?'selected':''?>>Left side</option></select></div>
        <div class="span2"><label>Hero Photo / Banner</label><input type="file" name="front_hero_image" accept="image/jpeg,image/png,image/webp"><small class="muted">JPG/PNG/WebP, maximum 5 MB. Upload your own banner image here; logo can be changed in Branding.</small></div>
        <div class="span2"><h3>🎨 Header colors & banner look</h3></div>
        <div><label>Header background color</label><input type="color" name="front_header_bg_color" value="<?=h(getSetting('front_header_bg_color','#ffffff'))?>"></div>
        <div><label style="display:flex;align-items:center;gap:8px"><input type="hidden" name="front_header_bg_transparent" value="0"><input type="checkbox" name="front_header_bg_transparent" value="1" <?=getSetting('front_header_bg_transparent','0')==='1'?'checked':''?>> Transparent header background (image ko color ke upar dikhayein)</label></div>
        <div><label>Header text color</label><input type="color" name="front_header_text_color" value="<?=h(getSetting('front_header_text_color','#075c37'))?>"></div>
        <div><label>Active menu/button color</label><input type="color" name="front_header_accent_color" value="<?=h(getSetting('front_header_accent_color','#08783e'))?>"></div>
        <div class="span2"><label>Header background artwork / branded name image</label><input id="frontHeaderArtworkInput" type="file" name="front_header_image" accept="image/jpeg,image/png,image/webp"><a class="btn small" href="?route=home&amp;header_test=1" target="_blank" rel="noopener">Preview built-in test image</a><small class="muted">JPG/PNG/WebP, max 5 MB and 10000 × 10000 px. Built-in test background abhi active hai (2688 × 1152 px). Apni JPG/PNG/WebP upload karne par yeh replace hogi. <span id="frontHeaderArtworkDimensions">Image ke actual dimensions yahan dikhte hain.</span> Current image: <?=h(getSetting('front_header_image','')?:'Built-in test header image is active')?><?php $currentHeaderFile=trim(getSetting('front_header_image','')); if($currentHeaderFile==='') $currentHeaderFile='assets/front-header-test.png'; $currentHeaderPath=__DIR__.'/'.ltrim($currentHeaderFile,'/'); $currentHeaderDims=is_file($currentHeaderPath)?@getimagesize($currentHeaderPath):false; if($currentHeaderDims): ?> (<?= (int)$currentHeaderDims[0] ?> × <?= (int)$currentHeaderDims[1] ?> px)<?php endif; ?></small></div>
        <div><label>Artwork size / image fit</label><select name="front_header_image_fit"><option value="contain" <?=trim(getSetting('front_header_image',''))!=='' && getSetting('front_header_image_fit','cover')==='contain'?'selected':''?>>Fit entire image (recommended for brand design)</option><option value="cover" <?=trim(getSetting('front_header_image',''))==='' || getSetting('front_header_image_fit','cover')==='cover'?'selected':''?>>Fill header (may crop edges)</option><option value="auto" <?=trim(getSetting('front_header_image',''))!=='' && getSetting('front_header_image_fit','cover')==='auto'?'selected':''?>>Original image size</option></select></div>
        <div><label>Header content with artwork</label><input type="hidden" name="front_header_artwork_only" value="0"><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="front_header_artwork_only" value="1" <?=getSetting('front_header_artwork_only','0')==='1'?'checked':''?>> Hide separate logo/name/tagline (artwork already contains branding)</label></div>
        <div class="span2"><small class="muted">“Fit entire image” image ka poora design dikhata hai; header height upar ke size control se adjust karein. “Fill header” edge crop kar sakta hai.</small></div>
        <div class="span2"><h3>📐 Header & Logo Size Controls</h3><p class="muted">Header height, Logo size और Home / Members / Reports / Notices की पतली menu line का font व padding अपने हिसाब से बड़ा-छोटा करें। Mobile पर चारों menu एक साथ एक line में दिखेंगे।</p></div>
        <div><label>Header height (px)</label><input type="number" name="front_header_height" min="48" max="180" value="<?=h(getSetting('front_header_height','76'))?>"></div>
        <div><label>Brand name text size (px)</label><input type="number" name="front_brand_name_size" min="12" max="48" value="<?=h(getSetting('front_brand_name_size','28'))?>"></div>
        <div><label>Brand tagline text size (px)</label><input type="number" name="front_brand_tagline_size" min="8" max="24" value="<?=h(getSetting('front_brand_tagline_size','17'))?>"></div>
        <div><label>Logo size (px)</label><input type="number" name="front_logo_size" min="28" max="130" value="<?=h(getSetting('front_logo_size','72'))?>"></div>
        <div><label>Menu font size (px)</label><input type="number" name="front_nav_font_size" min="8" max="22" value="<?=h(getSetting('front_nav_font_size','12'))?>"></div>
        <div><label>Menu line padding (px)</label><input type="number" name="front_nav_item_padding" min="2" max="16" value="<?=h(getSetting('front_nav_item_padding','7'))?>"></div>
        <div><label>Banner photo position</label><select name="front_banner_position"><option value="left" <?=getSetting('front_banner_position','left')==='left'?'selected':''?>>Focus left</option><option value="center" <?=getSetting('front_banner_position','left')==='center'?'selected':''?>>Center</option><option value="right" <?=getSetting('front_banner_position','left')==='right'?'selected':''?>>Focus right</option></select></div>
        <div><label>Banner overlay design</label><select name="front_banner_overlay"><option value="light" <?=getSetting('front_banner_overlay','light')==='light'?'selected':''?>>Soft white fade</option><option value="green" <?=getSetting('front_banner_overlay','light')==='green'?'selected':''?>>Green shade</option><option value="blue" <?=getSetting('front_banner_overlay','light')==='blue'?'selected':''?>>Blue shade</option><option value="none" <?=getSetting('front_banner_overlay','light')==='none'?'selected':''?>>No overlay</option></select></div>
        <div><label>Login Card Heading</label><input name="front_login_heading" value="<?=h(getSetting('front_login_heading','सदस्य एवं Admin Login'))?>"></div>
        <div><label>Member Login Button</label><input name="front_member_login_label" value="<?=h(getSetting('front_member_login_label','Member Login'))?>"></div>
        <div><label>Admin Login Button</label><input name="front_admin_login_label" value="<?=h(getSetting('front_admin_login_label','Admin Login'))?>"></div>
        <div class="span2"><h3>🎨 Front Page Text Colors</h3><p class="muted">Color picker se hero title, slogan aur login heading/buttons ke text (icon/arrow samet) ka rang badlein. Save karne ke baad front page refresh karein.</p></div>
        <div><label>GS Suraha title color</label><input type="color" name="front_hero_title_color" value="<?=h(getSetting('front_hero_title_color',in_array(getSetting('front_banner_overlay','light'),['green','blue'],true)?'#ffffff':'#006132'))?>"></div>
        <div><label>Slogan color</label><input type="color" name="front_hero_slogan_color" value="<?=h(getSetting('front_hero_slogan_color','#064d2d'))?>"></div>
        <div><label>Login heading color</label><input type="color" name="front_login_heading_color" value="<?=h(getSetting('front_login_heading_color','#075d35'))?>"></div>
        <div><label>Member Login text color</label><input type="color" name="front_member_login_color" value="<?=h(getSetting('front_member_login_color','#075c37'))?>"></div>
        <div><label>Admin Login text color</label><input type="color" name="front_admin_login_color" value="<?=h(getSetting('front_admin_login_color','#075c37'))?>"></div>
        <div><label>Hero Features Heading</label><input name="front_feature_heading" value="<?=h(getSetting('front_feature_heading','हमारी समिति की विशेषताएं'))?>"></div>
        <?php for($pi=1;$pi<=3;$pi++): ?><div><label>Hero promise <?=$pi?></label><input name="front_hero_promise_<?=$pi?>" value="<?=h(getSetting('front_hero_promise_'.$pi,(['सुरक्षित बचत और पारदर्शिता','सहयोग से समृद्धि का संकल्प','सभी के लिए सहायता'])[$pi-1]))?>"></div><?php endfor; ?>
        <div class="span2"><h3>🧭 Navigation & Sections</h3></div>
        <div><label>Home menu label</label><input name="front_nav_home" value="<?=h(getSetting('front_nav_home','Home'))?>"></div>
        <div><label>Members menu label</label><input name="front_nav_members" value="<?=h(getSetting('front_nav_members','Our Members'))?>"></div>
        <div><label>Reports menu label</label><input name="front_nav_reports" value="<?=h(getSetting('front_nav_reports','Reports'))?>"></div>
        <div><label>Notices menu label</label><input name="front_nav_notices" value="<?=h(getSetting('front_nav_notices','Notices'))?>"></div>
        <?php $frontToggles=['front_show_nav'=>'Navigation bar','front_show_nav_home'=>'Home menu link','front_show_nav_members'=>'Members menu link','front_show_nav_reports'=>'Reports menu link','front_show_nav_notices'=>'Notices menu link','front_show_hero'=>'Hero / welcome section','front_show_login'=>'Login card','front_show_members'=>'Members section','front_show_notices'=>'Notice ticker','front_show_latest_contribution'=>'Latest Contribution ticker','front_show_about'=>'About & Contact section','front_show_contribution'=>'Contribution call-to-action','front_show_features'=>'Features row']; foreach($frontToggles as $tk=>$tl): ?><div><label><?=h($tl)?></label><select name="<?=h($tk)?>"><option value="1" <?=getSetting($tk,'1')==='1'?'selected':''?>>Show</option><option value="0" <?=getSetting($tk,'1')==='0'?'selected':''?>>Hide</option></select></div><?php endforeach; ?>
        <div class="span2"><h3>📢 Notices & Contribution ticker</h3><p class="muted">Notice ticker ka heading yahan edit karein; har notice ka title/text Admin → Notices mein add/edit hota hai. Latest Contribution ke title aur display-message ko yahin customize karein. {date} aur {site} placeholders supported hain.</p></div>
        <div class="span2"><label>Notice ticker heading</label><input name="front_notice_title" value="<?=h(getSetting('front_notice_title','समिति की खबरें एवं सूचनाएं'))?>"></div>
        <div><label>Latest Contribution heading</label><input name="front_latest_contribution_title" value="<?=h(getSetting('front_latest_contribution_title','Latest Contribution'))?>"></div>
        <div class="span2"><label>Contribution message template</label><input name="front_latest_contribution_template" value="<?=h(getSetting('front_latest_contribution_template','A member contribution was received on {date} — thank you for supporting {site}.'))?>"></div>
        <div class="span2"><label>Contribution message when there are no recent payments</label><input name="front_latest_contribution_empty" value="<?=h(getSetting('front_latest_contribution_empty','Member contributions help strengthen our community and support society services.'))?>"></div>
        <div><label>Members section heading</label><input name="front_members_title" value="<?=h(getSetting('front_members_title','हमारे सदस्य'))?>"></div>
        <div><label>Members link label</label><input name="front_members_link_text" value="<?=h(getSetting('front_members_link_text','सभी सदस्य देखें »'))?>"></div>
        <div class="span2"><a class="btn" href="?route=control-center&amp;tab=notice">✏️ Manage notice messages</a></div>
        <div class="span2"><h3>📝 About, Contact & Contribution card</h3></div>
        <div><label>About section heading</label><input name="front_about_title" value="<?=h(getSetting('front_about_title','About Us / हमारे बारे में'))?>"></div>
        <div><label>Contact section heading</label><input name="front_contact_title" value="<?=h(getSetting('front_contact_title','Contact Us / संपर्क'))?>"></div>
        <div class="span2"><label>About text</label><textarea name="front_about_body" rows="3"><?=h(getSetting('front_about_body','GS Suraha Sahyog Samiti सदस्यों के सहयोग, सुरक्षित बचत और पारदर्शी सेवा के लिए बनाया गया platform है। '.$tagline))?></textarea></div>
        <div><label>Contribution card heading</label><input name="front_contribution_heading" value="<?=h(getSetting('front_contribution_heading','🤝 Contribution / सदस्य योगदान'))?>"></div>
        <div><label>Contribution button label</label><input name="front_contribution_button" value="<?=h(getSetting('front_contribution_button','Contribution के लिए Member Login →'))?>"></div>
        <div class="span2"><label>Contribution card text</label><textarea name="front_contribution_body" rows="2"><?=h(getSetting('front_contribution_body','समिति के सहयोग और विकास में अपना योगदान दें। अपना contribution देखने या जमा करने के लिए सदस्य लॉगिन करें।'))?></textarea></div>
        <div><label>Footer About label</label><input name="front_footer_about_label" value="<?=h(getSetting('front_footer_about_label','About'))?>"></div>
        <div><label>Footer Contact label</label><input name="front_footer_contact_label" value="<?=h(getSetting('front_footer_contact_label','Contact'))?>"></div>
        <div><label>Contact Phone</label><input name="contact_phone" value="<?=h(getSetting('contact_phone'))?>"></div><div><label>Contact Email</label><input type="email" name="contact_email" value="<?=h(getSetting('contact_email'))?>"></div><div class="span2"><label>Contact Address</label><textarea name="contact_address" rows="2"><?=h(getSetting('contact_address'))?></textarea></div>
        <div class="span2"><h3>✨ Feature cards</h3></div>
        <?php for($fi=1;$fi<=4;$fi++): ?><div><label>Feature <?=$fi?></label><input name="front_feature_<?=$fi?>" value="<?=h(getSetting('front_feature_'.$fi,(['सुरक्षित एवं विश्वसनीय प्लेटफॉर्म','सहयोग से समृद्धि','सशक्त सदस्य, समृद्ध समिति','24×7 सहायता'])[$fi-1]))?>"></div><?php endfor; ?>
        <div class="span2"><button class="btn primary">💾 Save All Front Page Settings</button> <a class="btn" target="_blank" href="?route=home">Preview Front Page</a></div>
      </form></div>
      <div class="panel"><div class="panel-head"><h2>ℹ️ Front Page Help</h2></div><p>Brand/logo ko Brand & Hero fields aur Admin → Branding se update karein. Desktop par selected login side ke neeche login card aur opposite upper corner mein heading/slogan dikhte hain; mobile layout automatically adjust hota hai.</p><p>Notice ticker ke messages Admin → Notices se manage hote hain. Latest Contribution ticker paid contribution dates se automatically banta hai; template mein <code>{date}</code> aur <code>{site}</code> edit kar sakte hain.</p><p>Section ko poori tarah chhupane ke liye uska control <b>Hide</b> karein. Changes sirf public front page par lagte hain; member/financial records nahi badalte.</p></div>
    </div>
    <?php elseif($tab==='site'): ?>
    <div class="panel"><div class="panel-head"><h2>⚙️ Site Settings</h2><span class="badge success">Live settings</span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings">
      <div><label>Site Name</label><input name="site_name" value="<?=h(getSetting('site_name',$settingsKeys['site_name']))?>"></div><div><label>App Download URL</label><input name="app_download_url" value="<?=h(getSetting('app_download_url',$settingsKeys['app_download_url']))?>" placeholder="https://your-site.com/download.php"><small class="muted">खाली छोड़ने पर site का /download.php link WhatsApp में जाएगा।</small></div><div><label>Tagline</label><input name="society_tagline" value="<?=h(getSetting('society_tagline',$settingsKeys['society_tagline']))?>"></div><div><label>Contact Phone</label><input name="contact_phone" value="<?=h(getSetting('contact_phone'))?>"></div><div><label>Contact Email</label><input name="contact_email" type="email" value="<?=h(getSetting('contact_email'))?>"></div><div class="span2"><label>Contact Address</label><textarea name="contact_address" rows="2"><?=h(getSetting('contact_address'))?></textarea></div><div><label>Primary Color</label><input name="primary_color" placeholder="#0f766e" value="<?=h(getSetting('primary_color'))?>"></div><div><label>Accent Color</label><input name="accent_color" placeholder="#2563eb" value="<?=h(getSetting('accent_color'))?>"></div><div class="span2"><button class="btn primary">💾 Save Site Settings</button></div></form></div>
    <?php elseif($tab==='notice'): ?>
    <?php $runningNotices=$db->query("SELECT id,title,body,enabled,created_at FROM notices WHERE enabled=1 ORDER BY id DESC"); $staticNoticeManager=trim(getSetting('notice_text','')); ?>
    <div class="notice-manager-grid">
      <div class="panel"><div class="panel-head"><h2>📢 Notice Manager</h2><span class="badge info">Notice control</span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="add_notice"><div class="span2"><label>Title</label><input name="title" placeholder="जैसे: Important Notice"></div><div class="span2"><label>Notice Text</label><textarea name="body" rows="4" required placeholder="Notice लिखें..."></textarea></div><div><label>Scroll Speed (seconds)</label><input type="number" name="notice_speed" value="<?=h(getSetting('notice_speed','35'))?>" min="5" max="180"></div><div><label>Move</label><select name="notice_move"><option value="1" <?=getSetting('notice_move','1')==='1'?'selected':''?>>ON / चले</option><option value="0" <?=getSetting('notice_move','1')==='0'?'selected':''?>>OFF / स्थिर</option></select></div><div><label>Notice Bar</label><select name="notice_enabled"><option value="1" <?=getSetting('notice_enabled','1')==='1'?'selected':''?>>Show</option><option value="0" <?=getSetting('notice_enabled','1')==='0'?'selected':''?>>Hide</option></select></div><div class="span2"><button class="btn primary">＋ Add Notice</button></div></form></div>

      <div class="panel notice-running-panel"><div class="panel-head"><div><h2>📋 अभी चल रहे Notice</h2><small class="muted">जो notice अभी member/admin dashboard पर दिख रहे हैं, वे यहाँ दिखाई देंगे।</small></div><span class="badge success">Live</span></div>
        <?php if($staticNoticeManager!==''): ?><div class="running-notice-row"><div class="running-notice-copy"><b>📌 Dashboard Notice</b><span><?=h($staticNoticeManager)?></span><small>Static notice · अभी चालू</small></div><form method="post" onsubmit="return confirm('यह Current Notice delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="clear_static_notice"><button class="btn small danger">🗑️ Delete</button></form></div><?php endif; ?>
        <?php $runningCount=0; while($rn=$runningNotices->fetchArray(SQLITE3_ASSOC)): $runningCount++; ?><div class="running-notice-row"><div class="running-notice-copy"><b><?=h(trim((string)$rn['title'])!=='' ? $rn['title'] : 'Notice #'.$rn['id'])?></b><span><?=h($rn['body'])?></span><small>🟢 अभी चालू · <?=h($rn['created_at'])?></small></div><div class="inline-form"><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="toggle_notice"><input type="hidden" name="id" value="<?=$rn['id']?>"><button class="btn small">⏸️ Hide</button></form><form method="post" onsubmit="return confirm('यह Notice permanently delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_notice"><input type="hidden" name="id" value="<?=$rn['id']?>"><button class="btn small danger">🗑️ Delete</button></form></div></div><?php endwhile; ?>
        <?php if($staticNoticeManager==='' && $runningCount===0): ?><div class="alert info">अभी कोई चालू Notice नहीं है।</div><?php endif; ?>
      </div>

      <?php
        // Dynamic contribution status messages also appear in the scrolling notice bar.
        // List them here so admins can dismiss a specific ticker message without deleting financial records.
        $contributionNoticeRows=[];
        $cr=$db->query("SELECT c.id,c.amount,c.status,c.created_at,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id ORDER BY c.id DESC LIMIT 12");
        while($cr && ($cx=$cr->fetchArray(SQLITE3_ASSOC))){
            $cs=(string)($cx['status']??'Pending');
            $ct=$cs==='Pending'?'Contribution verification pending':($cs==='Paid'?'Contribution payment verified':'Contribution payment rejected');
            $ck='contribution|'.(int)$cx['id']; // Stable key: status/title changes must not resurrect a dismissed contribution notice.
            $check=$db->prepare("SELECT 1 FROM activity_notice_dismissals WHERE user_id=? AND notice_key=? LIMIT 1");
            $check->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $check->bindValue(2,$ck,SQLITE3_TEXT);
            if(!$check->execute()->fetchArray(SQLITE3_NUM)) $contributionNoticeRows[]=['row'=>$cx,'title'=>$ct,'key'=>$ck];
        }
      ?>
      <?php
        // Loan application status notices are generated automatically in the ticker.
        // Dismissing them hides only the notice; the application, approval and EMI schedule remain untouched.
        $loanNoticeRows=[];
        $loanNoticeScope=(user()['role']??'')==='staff' ? 'WHERE la.assigned_staff_id='.(int)user()['id'] : '';
        $lr=$db->query("SELECT la.id,la.requested,la.status,la.created_at,m.name,m.code FROM loan_applications la JOIN members m ON m.id=la.member_id $loanNoticeScope ORDER BY la.id DESC LIMIT 12");
        while($lr && ($lx=$lr->fetchArray(SQLITE3_ASSOC))){
            $ls=(string)($lx['status']??'Pending');
            $lt=$ls==='Pending'?'Loan application verification pending':($ls==='Forwarded'?'Loan application forwarded to Admin':($ls==='Approved'?'Loan application approved':'Loan application rejected'));
            $lh='?route=loan-applications&focus='.(int)$lx['id'];
            $lk='loan|'.(int)$lx['id'];
            $check=$db->prepare("SELECT 1 FROM activity_notice_dismissals WHERE user_id=? AND notice_key=? LIMIT 1");
            $check->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $check->bindValue(2,$lk,SQLITE3_TEXT);
            if(!$check->execute()->fetchArray(SQLITE3_NUM)) $loanNoticeRows[]=['row'=>$lx,'title'=>$lt,'key'=>$lk];
        }
      ?>
      <div class="panel notice-running-panel">
        <div class="panel-head"><div><h2>🏦 Loan Status Notices</h2><small class="muted">Approved / Pending / Rejected loan application के automatic scrolling notices. Delete करने से loan record, approval status और EMI schedule नहीं हटेंगे।</small></div><span class="badge info"><?=count($loanNoticeRows)?> notices</span></div>
        <?php if(!$loanNoticeRows): ?><div class="alert info">अभी कोई loan status notice नहीं है, या सभी हटाए जा चुके हैं।</div><?php else: foreach($loanNoticeRows as $ln): $lx=$ln['row']; ?>
          <div class="running-notice-row"><div class="running-notice-copy"><b><?=h($ln['title'])?></b><span>🏦 <?=h((string)$lx['name'])?> (<?=h((string)$lx['code'])?>) — <?=h(money((float)$lx['requested']))?> · Status: <?=h((string)$lx['status'])?></span><small><?=h((string)$lx['created_at'])?></small></div><form method="post" action="?route=control-center&tab=notice" onsubmit="return confirm('इस loan status notice को हटाएँ? Loan record और approval सुरक्षित रहेंगे।')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_activity_notice"><input type="hidden" name="notice_key" value="<?=h($ln['key'])?>"><button class="btn small danger" type="submit">🗑️ Delete Notice</button></form></div>
        <?php endforeach; endif; ?>
      </div>
      <div class="panel notice-running-panel">
        <div class="panel-head"><div><h2>💰 Contribution Status Notices</h2><small class="muted">Verified / Pending / Rejected contribution messages जो scrolling notice में दिखते हैं। Delete करने से केवल notice छिपेगा; contribution record सुरक्षित रहेगा।</small></div><span class="badge info"><?=count($contributionNoticeRows)?> notices</span></div>
        <?php if(!$contributionNoticeRows): ?><div class="alert info">अभी कोई contribution status notice नहीं है, या सभी हटाए जा चुके हैं।</div><?php else: foreach($contributionNoticeRows as $cn): $cx=$cn['row']; ?>
          <div class="running-notice-row"><div class="running-notice-copy"><b><?=h($cn['title'])?></b><span>💰 <?=h((string)$cx['name'])?> (<?=h((string)$cx['code'])?>) — <?=h(money((float)$cx['amount']))?> · Status: <?=h((string)$cx['status'])?></span><small><?=h((string)$cx['created_at'])?></small></div><form method="post" action="?route=control-center&tab=notice" onsubmit="return confirm('इस contribution notice को हटाएँ? Contribution record सुरक्षित रहेगा।')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_activity_notice"><input type="hidden" name="notice_key" value="<?=h($cn['key'])?>"><button class="btn small danger" type="submit">🗑️ Delete Notice</button></form></div>
        <?php endforeach; endif; ?>
      </div>
      <div class="panel notice-all-panel"><div class="panel-head"><div><h2>🗂️ सभी Notice</h2><small class="muted">Hidden notice भी यहाँ से फिर चालू या delete कर सकते हैं।</small></div></div><div class="table-wrap"><table><thead><tr><th>Notice</th><th>Status</th><th>Date</th><th>Action</th></tr></thead><tbody><?php while($n=$notices->fetchArray(SQLITE3_ASSOC)): ?><tr><td><b><?=h(trim((string)$n['title'])!=='' ? $n['title'] : 'Notice #'.$n['id'])?></b><br><?=h($n['body'])?></td><td><?=((int)$n['enabled']?'🟢 Running':'⚪ Hidden')?></td><td><?=h($n['created_at'])?></td><td><div class="inline-form"><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="toggle_notice"><input type="hidden" name="id" value="<?=$n['id']?>"><button class="btn small"><?=((int)$n['enabled'])?'Hide':'Show'?></button></form><form method="post" onsubmit="return confirm('Delete this notice permanently?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_notice"><input type="hidden" name="id" value="<?=$n['id']?>"><button class="btn small danger">🗑️ Delete</button></form></div></td></tr><?php endwhile; ?></tbody></table></div></div>
    </div>
    <?php elseif($tab==='branding'): ?>
    <div class="grid-2"><?php foreach(['logo'=>'Logo','banner'=>'Banner','favicon'=>'Favicon'] as $bk=>$bl): ?><div class="panel"><h2>🖼️ <?=h($bl)?></h2><p class="muted">Current: <?=h(getSetting($bk==='logo'?'header_logo':($bk==='banner'?'header_banner':'site_favicon'),''))?></p><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="upload_branding"><input type="hidden" name="brand_field" value="<?=$bk?>"><input type="file" name="branding_file" accept="image/png,image/jpeg,image/webp,image/x-icon" required><button class="btn primary" style="margin-top:10px">Upload <?=h($bl)?></button></form><form method="post" style="margin-top:8px" onsubmit="return confirm('<?=h($bl)?> reset/delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_branding"><input type="hidden" name="brand_field" value="<?=$bk?>"><button class="btn small danger" type="submit">Delete / Reset <?=h($bl)?></button></form></div><?php endforeach; ?></div>
    <?php elseif(in_array($tab,['summary','affidavit','agreement'],true)): ?>
    <?php $dtype=$tab; $prefix=$dtype==='summary'?'doc_summary':($dtype==='affidavit'?'doc_affidavit':'doc_agreement'); $titleKey=$prefix.'_title'; $subKey=$prefix.'_subtitle'; $defTitle=$settingsKeys[$titleKey]; $defSub=$settingsKeys[$subKey]; ?>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><div><h2><?= $dtype==='summary'?'📊 Summary Designer':($dtype==='affidavit'?'📄 Affidavit Designer':'🤝 Agreement Designer') ?></h2><small class="muted">Title और subtitle को Admin Panel से बदलें।</small></div><span class="badge success">Live</span></div>
      <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings">
        <label>Title / शीर्षक</label><input name="<?=$titleKey?>" value="<?=h(getSetting($titleKey,$defTitle))?>">
        <label style="margin-top:10px">Subtitle / उप-शीर्षक</label><input name="<?=$subKey?>" value="<?=h(getSetting($subKey,$defSub))?>">
        <button class="btn primary full" style="margin-top:16px">💾 Save <?=ucfirst($dtype)?> Design</button>
      </form>
      <form method="post" style="margin-top:10px"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="reset_design"><input type="hidden" name="design_type" value="<?=$dtype?>"><button class="btn danger full" onclick="return confirm('<?=$dtype?> का पुराना/default design वापस लाएँ?')">↩ Reset to Original Design</button></form>
      </div>
      <div class="panel"><h2>👀 Preview</h2><div style="border:1px solid #dce4ef;border-radius:12px;padding:22px;background:#fff;text-align:center"><div style="font-size:22px;font-weight:800"><?=h(getSetting($titleKey,$defTitle))?></div><div style="margin-top:6px;color:#64748b;font-size:15px"><?=h(getSetting($subKey,$defSub))?></div><hr style="margin:18px 0"><p class="muted">यह title/subtitle संबंधित <?=$dtype?> document में दिखेगा।</p></div></div>
    </div>
    <?php elseif($tab==='loan'): ?>
    <div class="panel"><div class="panel-head"><h2>💰 Loan & EMI Settings</h2></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings"><div><label>Interest Rate %</label><input name="loan_interest_rate" type="number" step="0.01" value="<?=h(getSetting('loan_interest_rate'))?>"></div><div><label>Default Tenure (Months)</label><input name="loan_default_tenure" type="number" min="1" value="<?=h(getSetting('loan_default_tenure','12'))?>"></div><div><label>Penalty Rate %</label><input name="loan_penalty_rate" type="number" step="0.01" value="<?=h(getSetting('loan_penalty_rate'))?>"></div><div><label>Loan Eligibility %</label><input name="loan_eligibility_percent" type="number" step="1" value="<?=h(getSetting('loan_eligibility_percent','80'))?>"></div><div><label>Monthly Contribution ₹</label><input name="monthly_contribution" type="number" step="0.01" value="<?=h(getSetting('monthly_contribution','0'))?>"></div><div class="span2"><button class="btn primary">💾 Save Loan Settings</button></div></form></div>
    <?php elseif($tab==='security'): ?>
    <div class="panel"><div class="panel-head"><h2>🔐 Security Settings</h2><span class="badge warning">Super Admin</span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings"><div><label>Session Timeout (minutes)</label><input name="session_timeout_minutes" type="number" min="5" max="1440" value="<?=h(getSetting('session_timeout_minutes','60'))?>"></div><div><label>Member Mobile Lock</label><select name="mobile_lock"><option value="1" <?=getSetting('mobile_lock','1')==='1'?'selected':''?>>🔒 Locked</option><option value="0" <?=getSetting('mobile_lock')==='0'?'selected':''?>>Unlocked</option></select></div><div><label>Maintenance Mode</label><select name="maintenance_mode"><option value="0" <?=getSetting('maintenance_mode','0')==='0'?'selected':''?>>Normal</option><option value="1" <?=getSetting('maintenance_mode')==='1'?'selected':''?>>🔧 Maintenance ON</option></select></div><div class="span2"><button class="btn primary">💾 Save Security</button></div></form><div class="alert info">Super Admin को छोड़कर अन्य users maintenance mode में site नहीं खोल पाएँगे।</div></div>
    <?php elseif($tab==='legal'): ?>
    <div class="panel"><div class="panel-head"><h2>📝 Terms / Privacy / Footer</h2></div><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings"><label>Terms & Conditions</label><textarea name="terms_text" rows="6"><?=h(getSetting('terms_text'))?></textarea><label style="margin-top:12px">Privacy Policy</label><textarea name="privacy_text" rows="6"><?=h(getSetting('privacy_text'))?></textarea><label style="margin-top:12px">Footer Text</label><input name="footer_text" value="<?=h(getSetting('footer_text'))?>"><button class="btn primary" style="margin-top:12px">💾 Save Legal Content</button></form></div>
    <?php elseif($tab==='menus'): ?>
    <div class="panel"><div class="panel-head"><h2>💰 Loan Interest Distribution</h2><span class="badge info">Automatic Ledger</span></div><div class="kpis"><div class="kpi blue"><span>Loan Interest Collected</span><b><?=money((float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections"))?></b></div><div class="kpi green"><span>Credited to Members</span><b><?=money((float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger"))?></b></div><div class="kpi orange"><span>Not Yet Allocated</span><b><?=money(max(0,(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections")-(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger")))?></b></div></div><div class="alert info">Verified EMI का केवल वसूला हुआ ब्याज—मूलधन नहीं—सभी Active सदस्यों में उनके उस समय तक के Paid Contribution अनुपात से बाँटा जाता है। हर Member का हिस्सा उसके Interest Ledger में जमा होता है।</div></div><div class="panel"><div class="panel-head"><h2>🎨 Menu / Page Settings</h2></div><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_control_settings"><div class="settings-grid"><?php foreach(['members'=>'Members','loans'=>'Loans & EMI','payments'=>'Payments','reports'=>'Reports','notifications'=>'Notifications'] as $mk=>$ml): ?><label style="display:flex;gap:10px;align-items:center"><input type="hidden" name="menu_<?=$mk?>" value="0"><input type="checkbox" name="menu_<?=$mk?>" value="1" <?=getSetting('menu_'.$mk,'1')==='1'?'checked':''?>> <?=h($ml)?> menu visible</label><?php endforeach; ?></div><button class="btn primary" style="margin-top:15px">💾 Save Menu Settings</button></form></div>
    <?php elseif($tab==='payment'): ?>
    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><div><h2>💳 Payment System</h2><small class="muted">UPI, QR, Payment API और payment verification को यहीं से manage करें।</small></div><span class="badge success">A2Z Control</span></div>
        <form method="post" class="settings-grid">
          <input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_payment_system">
          <div><label>Monthly Fixed Contribution (₹)</label><input name="monthly_contribution" type="number" step="0.01" value="<?=h(getSetting('monthly_contribution','0'))?>"></div>
          <div><label>Maximum Loan Against Deposit (%)</label><input name="loan_eligibility_percent" type="number" step="0.01" min="0" max="100" value="<?=h(getSetting('loan_eligibility_percent','80'))?>"></div>
          <div class="span2"><h3 style="margin:8px 0 0">📱 UPI / QR Payment</h3></div>
          <div><label>UPI ID / Merchant VPA</label><input name="upi_id" value="<?=h(getSetting('upi_id',''))?>" placeholder="example@upi"></div>
          <div><label>UPI Display Name</label><input name="upi_name" value="<?=h(getSetting('upi_name','GS Suraha Sahyog Samiti'))?>"></div>
          <div class="span2"><div class="settings-checks"><label><input type="hidden" name="payment_allow_member_upi" value="0"><input type="checkbox" name="payment_allow_member_upi" value="1" <?=getSetting('payment_allow_member_upi','1')==='1'?'checked':''?>> Member को UPI App से payment</label><label><input type="hidden" name="payment_allow_qr" value="0"><input type="checkbox" name="payment_allow_qr" value="1" <?=getSetting('payment_allow_qr','1')==='1'?'checked':''?>> QR Code payment</label><label><input type="hidden" name="payment_require_reference" value="0"><input type="checkbox" name="payment_require_reference" value="1" <?=getSetting('payment_require_reference','1')==='1'?'checked':''?>> Transaction/reference required</label></div></div>
          <div class="span2"><h3 style="margin:8px 0 0">🌐 Payment Gateway API</h3></div>
          <div class="span2"><label>Payment API URL</label><input name="payment_api_url" value="<?=h(getSetting('payment_api_url',''))?>" placeholder="https://your-gateway.example/checkout"></div>
          <div><label>Payment API Key</label><input name="payment_api_key" type="password" value="<?=h(getSetting('payment_api_key',''))?>" autocomplete="new-password"></div>
          <div><label>Payment API Secret</label><input name="payment_api_secret" type="password" value="<?=h(getSetting('payment_api_secret',''))?>" autocomplete="new-password"></div>
          <div class="span2"><div class="settings-checks"><label><input type="hidden" name="payment_api_enabled" value="0"><input type="checkbox" name="payment_api_enabled" value="1" <?=getSetting('payment_api_enabled','0')==='1'?'checked':''?>> Payment API Enabled</label><label><input type="hidden" name="payment_allow_api" value="0"><input type="checkbox" name="payment_allow_api" value="1" <?=getSetting('payment_allow_api','1')==='1'?'checked':''?>> Member को API payment option</label><label><input type="hidden" name="payment_auto_verify" value="0"><input type="checkbox" name="payment_auto_verify" value="1" <?=getSetting('payment_auto_verify','0')==='1'?'checked':''?>> Auto verify (केवल gateway callback पर)</label></div></div>
          <div class="span2"><h3 style="margin:8px 0 0">🧾 Payment Slip / Send Slip</h3></div>
          <div class="span2"><div class="settings-checks"><label><input type="hidden" name="payment_slip_enabled" value="0"><input type="checkbox" name="payment_slip_enabled" value="1" <?=getSetting('payment_slip_enabled','1')==='1'?'checked':''?>> Payment Slip enabled</label><label><input type="hidden" name="payment_send_slip_admin" value="0"><input type="checkbox" name="payment_send_slip_admin" value="1" <?=getSetting('payment_send_slip_admin','1')==='1'?'checked':''?>> Admin can Send Slip</label><label><input type="hidden" name="payment_send_slip_staff" value="0"><input type="checkbox" name="payment_send_slip_staff" value="1" <?=getSetting('payment_send_slip_staff','1')==='1'?'checked':''?>> Staff can Send Slip</label></div></div>
          <div class="span2"><button class="btn primary">💾 Save Payment System</button></div>
        </form>
      </div>
      <div>
        <div class="panel"><div class="panel-head"><h2>🔐 Payment Status</h2></div><div class="settings-checks"><div>UPI ID: <b><?=h(getSetting('upi_id','Not configured'))?></b></div><div>Payment API: <b><?=getSetting('payment_api_enabled','0')==='1'?'Enabled':'Disabled'?></b></div><div>Payment Slip: <b><?=getSetting('payment_slip_enabled','1')==='1'?'Enabled':'Disabled'?></b></div><div>Admin Send Slip: <b><?=getSetting('payment_send_slip_admin','1')==='1'?'Allowed':'Blocked'?></b></div><div>Staff Send Slip: <b><?=getSetting('payment_send_slip_staff','1')==='1'?'Allowed':'Blocked'?></b></div></div></div>
        <div class="panel"><h2>ℹ️ Payment Flow</h2><p class="muted">Member payment → Pending → Admin/Staff verification → Paid → Payment Slip. UPI/QR settings यहाँ से control होंगे।</p><p class="muted">API credentials खाली होने पर कोई real gateway transaction अपने-आप नहीं होगा।</p></div>
      </div>
    </div>
    <?php elseif($tab==='slip'): ?>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><div><h2>🧾 Payment Slip Designer</h2><small class="muted">Payment/collection slip का design बिना code बदले बदलें।</small></div><span class="badge success">Live</span></div>
      <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_slip_design">
      <div class="grid-2"><div><label>Primary Color</label><input type="color" name="slip_primary" value="<?=h(getSetting('slip_primary','#0b65d5'))?>"></div><div><label>Secondary Color</label><input type="color" name="slip_secondary" value="<?=h(getSetting('slip_secondary','#06265b'))?>"></div><div><label>Text Color</label><input type="color" name="slip_text" value="<?=h(getSetting('slip_text','#17324d'))?>"></div><div><label>Border Radius</label><input type="number" min="0" max="30" name="slip_border_radius" value="<?=h(getSetting('slip_border_radius','12'))?>"></div><div><label>Hindi Title</label><input name="slip_title_hi" value="<?=h(getSetting('slip_title_hi','भुगतान रसीद'))?>"></div><div><label>English Title</label><input name="slip_title_en" value="<?=h(getSetting('slip_title_en','PAYMENT RECEIPT'))?>"></div><div class="span2"><label>Footer Text</label><input name="slip_footer" value="<?=h(getSetting('slip_footer','धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।'))?>"></div></div>
      <div class="settings-checks"><label><input type="checkbox" name="slip_show_logo" value="1" <?=getSetting('slip_show_logo','1')==='1'?'checked':''?>> Logo</label><label><input type="checkbox" name="slip_show_member" value="1" <?=getSetting('slip_show_member','1')==='1'?'checked':''?>> Member Details</label><label><input type="checkbox" name="slip_show_date" value="1" <?=getSetting('slip_show_date','1')==='1'?'checked':''?>> Date & Time</label><label><input type="checkbox" name="slip_show_mode" value="1" <?=getSetting('slip_show_mode','1')==='1'?'checked':''?>> Payment Mode</label><label><input type="checkbox" name="slip_show_reference" value="1" <?=getSetting('slip_show_reference','1')==='1'?'checked':''?>> Reference No.</label><label><input type="checkbox" name="slip_show_status" value="1" <?=getSetting('slip_show_status','1')==='1'?'checked':''?>> Status</label><label><input type="checkbox" name="slip_show_note" value="1" <?=getSetting('slip_show_note','1')==='1'?'checked':''?>> Note/Footer</label></div><button class="btn primary full">💾 Save Slip Design</button><div class="inline-form" style="margin-top:10px"><button type="submit" form="reset-slip-form" class="btn danger" onclick="return confirm('Slip का पुराना/default design वापस लाएँ?')">↩ Reset to Original</button></div></form></div>
      <form id="reset-slip-form" method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="reset_design"><input type="hidden" name="design_type" value="slip"></form>
      <div class="panel"><h2>👀 Live Preview</h2><div style="border:2px solid <?=h(getSetting('slip_primary','#0b65d5'))?>;border-radius:<?=h(getSetting('slip_border_radius','12'))?>px;overflow:hidden;color:<?=h(getSetting('slip_text','#17324d'))?>;background:#fff"><div style="background:<?=h(getSetting('slip_primary','#0b65d5'))?>;color:#fff;padding:18px;text-align:center"><b><?=h(getSetting('slip_title_en','PAYMENT RECEIPT'))?></b><div><?=h(getSetting('slip_title_hi','भुगतान रसीद'))?></div></div><div style="padding:18px"><p><b>GS Suraha Finance</b></p><p>Member Name: Demo Member</p><p>Member ID: GS001</p><p>Amount Paid: ₹1,000.00</p><p>Payment Mode: UPI</p><p>Reference No.: TXN12345</p><hr><small><?=h(getSetting('slip_footer','धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।'))?></small></div></div><p class="muted" style="margin-top:12px">Save करने के बाद payment receipt में यह design इस्तेमाल होगा।</p></div></div>
    <?php elseif($tab==='backup'): ?>
    <div class="grid-2"><div class="panel"><h2>💾 Database Backup</h2><p class="muted">Current database का सुरक्षित backup download करें।</p><a class="btn primary" href="?route=backup">⬇ Download Backup</a></div><div class="panel"><h2>♻️ Restore</h2><p class="muted">Restore से पहले automatic safety copy बनाई जाएगी।</p><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="restore_db"><input type="file" name="restore_file" accept=".sqlite,.db" required><button class="btn danger" style="margin-top:10px" onclick="return confirm('Restore database? Current database will be backed up first.')">♻ Restore Database</button></form></div></div>
    <?php elseif($tab==='audit'): ?>
    <div class="panel"><div class="panel-head"><h2>🧾 Activity / Audit Log</h2><span class="badge info">Last 100 actions</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Admin</th><th>Action</th><th>Details</th></tr></thead><tbody><?php while($a=$auditRows->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h($a['created_at'])?></td><td><?=h($a['username']??'System')?></td><td><b><?=h($a['action'])?></b></td><td><?=h($a['details'])?></td></tr><?php endwhile; ?></tbody></table></div></div>
    <?php endif; ?>
    <div class="panel" style="margin-top:16px"><div class="panel-head"><h2>👤 Admin / Staff Permissions</h2><a class="btn small" href="?route=admin-users">Manage Admin IDs →</a></div><p class="muted">दूसरे Admin को अलग-अलग permissions देने के लिए Admin IDs में जाकर capabilities चुनें। Super Admin को सभी controls मिलते हैं।</p></div>
    <?php $c=ob_get_clean(); layout('A2Z Control Center',$c); exit;
}

if($route==='admin-panel'){
    requireLogin(); if(!isSuperAdmin()){ http_response_code(403); exit('Super Admin only'); }
    $activeMembers=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");
    $totalMembers=(int)$db->querySingle("SELECT COUNT(*) FROM members");
    $pendingLoans=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Forwarded'");
    $pendingPayments=(int)$db->querySingle("SELECT COUNT(*) FROM payments WHERE status='Pending'");
    $activeLoans=(int)$db->querySingle("SELECT COUNT(*) FROM loans WHERE status='Active'");
    $overdue=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status!='Paid' AND due_date<date('now')");
    $adminCount=(int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role='admin'");
    $staffCount=(int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role='staff'"); $limitedAdminCount=(int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role='admin' AND is_super_admin=0");
    $lastLogin=(string)($_SESSION['login_time']??'');
    ob_start(); ?>
    <div class="hero modern-dashboard-hero"><div class="dashboard-welcome"><div class="dashboard-welcome-copy"><div class="eyebrow">ADMIN CONTROL CENTER</div><h1>Admin Panel ⚙️</h1><p>GS Suraha Finance की पूरी administration एक जगह से manage करें।</p></div></div><a class="btn light" href="?route=dashboard">← Main Dashboard</a></div>
    <div class="kpis modern-kpis">
      <div class="kpi blue"><span>👥 Active Members</span><b><?=number_format($activeMembers)?></b><small>Total: <?=number_format($totalMembers)?></small></div>
      <div class="kpi purple"><span>💰 Active Loans</span><b><?=number_format($activeLoans)?></b><small>Current loan accounts</small></div>
      <div class="kpi orange"><span>📝 Loan Review</span><b><?=number_format($pendingLoans)?></b><small>Forwarded to Admin</small></div>
      <div class="kpi red"><span>💳 Pending Payments</span><b><?=number_format($pendingPayments)?></b><small>Need verification</small></div>
      <div class="kpi pink"><span>⏰ Overdue EMI</span><b><?=number_format($overdue)?></b><small>Past due installments</small></div>
      <div class="kpi teal"><span>🔐 Admin IDs</span><b><?=number_format($adminCount)?></b><small>Staff: <?=number_format($staffCount)?> · Limited Admin: <?=number_format($limitedAdminCount)?></small></div>
    </div>
    <div class="panel feature-panel"><div class="panel-head"><div><h2>Administration</h2><small class="muted">Important controls and daily operations</small></div><span class="badge success">Admin Only</span></div>
      <div class="feature-grid">
        <a class="feature-card fc-blue" href="?route=members"><span>👥</span><div><b>Members</b><small>Add, view and manage member records</small></div></a>
        <a class="feature-card fc-purple" href="?route=loan-applications"><span>📄</span><div><b>Loan Applications</b><small>Review and approve forwarded applications</small></div><em><?=$pendingLoans?></em></a>
        <a class="feature-card fc-orange" href="?route=loans"><span>💰</span><div><b>Loans & EMI</b><small>Loan accounts, schedules and agreements</small></div></a>
        <a class="feature-card fc-green" href="?route=emi-payments"><span>💳</span><div><b>Payment Verification</b><small>Verify pending EMI/payment records</small></div><em><?=$pendingPayments?></em></a>
        <a class="feature-card fc-teal" href="?route=contributions"><span>₹</span><div><b>Contributions</b><small>Deposits and contribution records</small></div></a>
        <a class="feature-card fc-red" href="?route=contribution-reminders"><span>💰</span><div><b>Contribution Reminders</b><small>Pending monthly contribution reminders</small></div></a>
        <a class="feature-card fc-violet" href="?route=emi-reminders"><span>🔔</span><div><b>EMI Reminders</b><small>Pending EMI and overdue reminders</small></div></a>
        <a class="feature-card fc-blue" href="?route=reports"><span>📊</span><div><b>Reports</b><small>Financial and collection reports</small></div></a>
        <a class="feature-card fc-pink" href="?route=communications"><span>📱</span><div><b>WhatsApp & SMS</b><small>Communication settings and sending</small></div></a>
        <a class="feature-card fc-orange" href="?route=fund-adjustments"><span>📉</span><div><b>Expenses & Withdrawals</b><small>Manage admin fund adjustments</small></div></a>
        <a class="feature-card fc-green" href="?route=interest-refund-settings"><span>🧮</span><div><b>Interest & Refund Settings</b><small>Reserve, annual equal benefit, payouts and audit trail</small></div></a>
        <a class="feature-card fc-indigo" href="?route=control-center"><span>⚙️</span><div><b>A2Z Control Center</b><small>Site, Notice, Branding, Loan, Security, Backup & more</small></div></a>
        <a class="feature-card fc-teal" href="?route=admin-users"><span>👤</span><div><b>Admin IDs</b><small>Create, edit and secure admin accounts</small></div></a>
        <a class="feature-card fc-violet" href="?route=staff-member-users"><span>👥</span><div><b>Staff & Member IDs</b><small>Manage staff/member login accounts</small></div></a>
        <a class="feature-card fc-blue" href="?route=backup"><span>💾</span><div><b>Backup</b><small>Download and preserve database backup</small></div></a>
        <a class="feature-card fc-green" href="?route=notifications"><span>🔔</span><div><b>Notifications</b><small>Member and system notifications</small></div></a>
      </div>
    </div>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><div><h2>🔒 Security Status</h2><small class="muted">Current application protections</small></div><span class="badge success">Protected</span></div>
        <div class="profile-grid"><div><b>CSRF Protection</b><span>Enabled</span></div><div><b>Secure Sessions</b><span>HttpOnly / SameSite</span></div><div><b>Database</b><span>SQLite + prepared statements</span></div><div><b>Member Phone</b><span>Member locked / Admin only</span></div><div><b>Upload Protection</b><span>PHP execution blocked</span></div><div><b>Session Timeout</b><span>Enabled</span></div></div>
        <div class="alert info" style="margin-top:14px">Security changes should be made only by authorized Admin users. Never share passwords, API keys or database files publicly.</div>
      </div>
      <div class="panel"><div class="panel-head"><div><h2>👤 Current Admin</h2><small class="muted">Current session information</small></div></div>
        <div class="profile-grid"><div><b>Name</b><span><?=h(user()['display_name']?:'Administrator')?></span></div><div><b>Admin ID</b><span><?=h(user()['username'])?></span></div><div><b>Role</b><span>Administrator</span></div><div><b>Login Time</b><span><?=h($lastLogin?:'Current session')?></span></div></div>
        <div class="inline-form" style="margin-top:16px"><a class="btn primary" href="?route=admin-users&edit=<?=((int)user()['id'])?>">Change Admin Password</a><a class="btn" href="?route=backup">Backup</a></div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Admin Panel',$c); exit;
}

if($route==='dashboard'){
    requireRole(['admin','staff']);
    $members=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");
    $deposits=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'");
    $loans=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans WHERE status='Active'");
    $outstanding=(float)$db->querySingle("SELECT COALESCE(SUM(MAX(amount-paid_amount,0)),0) FROM emi_schedule");
    $localTodaySql=SQLite3::escapeString(date('Y-m-d')); $overdue=(float)$db->querySingle("SELECT COALESCE(SUM(MAX(amount-paid_amount,0)),0) FROM emi_schedule WHERE status!='Paid' AND due_date<'{$localTodaySql}'");
    $pending=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Pending' AND assigned_staff_id=".(int)user()['id']);
    if(user()['role']==='admin') $pending=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Forwarded'");
    $month=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid' AND month='".date('Y-m')."'");
    $monthly=getSetting('monthly_contribution','0'); $elig=getSetting('loan_eligibility_percent','80');

    // Admin fund / loan-profit accounting:
    // Available fund = contributions received + EMI cash received - principal disbursed.
    // Interest/profit is separated from EMI collections instead of treating the full EMI as profit.
    $totalContribution=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'");
    $closedRefunds=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE status='Approved'");
    $loanPrincipalDisbursed=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans");
    $emiCashReceived=(float)$db->querySingle("SELECT COALESCE(SUM(paid_amount),0) FROM emi_schedule");
    $scheduledEmiTotal=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM emi_schedule");
    $interestProfit=0.0;
    $loanAccountingRows=$db->query("SELECT l.principal,
        COALESCE((SELECT SUM(amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) total_emi,
        COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) paid_emi
        FROM loans l");
    if($loanAccountingRows){
        while($ar=$loanAccountingRows->fetchArray(SQLITE3_ASSOC)){
            $principal=(float)$ar['principal']; $totalEmi=(float)$ar['total_emi']; $paidEmi=(float)$ar['paid_emi'];
            $scheduledInterest=max(0,$totalEmi-$principal);
            if($totalEmi>0 && $paidEmi>0) $interestProfit += min($scheduledInterest, $scheduledInterest*min(1,$paidEmi/$totalEmi));
        }
    }
    $principalRecovered=max(0,$emiCashReceived-$interestProfit);
    $loanBalance=max(0,$loanPrincipalDisbursed-$principalRecovered);
    $fundAdjustments=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM fund_adjustments");
    $availableFund=max(0,$totalContribution+$emiCashReceived-$loanPrincipalDisbursed-$fundAdjustments-$closedRefunds);
    $availableLoanAgainstDeposit=$totalContribution*(float)$elig/100;
    $availableForNewLoan=max(0,$availableFund);
    $rows=$db->query("SELECT m.name,m.code,COALESCE(SUM(c.amount),0) total FROM members m LEFT JOIN contributions c ON c.member_id=m.id AND c.status='Paid' WHERE m.status='Active' GROUP BY m.id ORDER BY total DESC LIMIT 6");

    // Recent activity feed for admin dashboard
    $adminActivity=[];
    try{
        $ar=$db->query("SELECT 'member' t, name label, code sub, created_at ts FROM members ORDER BY id DESC LIMIT 5");
        while($ar && ($r=$ar->fetchArray(SQLITE3_ASSOC))) $adminActivity[]=['type'=>'member','title'=>'New member registered','desc'=>h($r['label']).' joined the samiti','time'=>$r['ts'],'status'=>'Completed'];
    }catch(Throwable $e){}
    try{
        $ar=$db->query("SELECT c.amount,c.created_at,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Paid' ORDER BY c.id DESC LIMIT 5");
        while($ar && ($r=$ar->fetchArray(SQLITE3_ASSOC))) $adminActivity[]=['type'=>'contrib','title'=>'Contribution received','desc'=>money((float)$r['amount']).' received from '.h($r['name']),'time'=>$r['created_at'],'status'=>'Completed'];
    }catch(Throwable $e){}
    try{
        $ar=$db->query("SELECT la.created_at,m.name,m.code,la.status FROM loan_applications la JOIN members m ON m.id=la.member_id ORDER BY la.id DESC LIMIT 5");
        while($ar && ($r=$ar->fetchArray(SQLITE3_ASSOC))) $adminActivity[]=['type'=>'loan','title'=>'Loan application forwarded','desc'=>'Application from '.h($r['name']).' — '.h($r['status']),'time'=>$r['created_at'],'status'=>h($r['status'])];
    }catch(Throwable $e){}
    usort($adminActivity, static fn($a,$b)=>strtotime((string)$b['time'])<=>strtotime((string)$a['time']));
    $adminActivity=array_slice($adminActivity,0,6);

    // Last 6 months collection for chart
    $chartMonths=[]; $chartMax=1.0;
    for($i=5;$i>=0;$i--){
        $ym=date('Y-m', strtotime("-{$i} months"));
        $label=date('M', strtotime($ym.'-01'));
        $amt=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid' AND month='".SQLite3::escapeString($ym)."'");
        $chartMonths[]=['label'=>$label,'amount'=>$amt];
        if($amt>$chartMax) $chartMax=$amt;
    }
    $membersThisMonth=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active' AND strftime('%Y-%m',created_at)='".date('Y-m')."'");

    ob_start(); ?>
<div class="ad-dash">
  <!-- Welcome -->
  <section class="ad-welcome">
    <div class="ad-welcome-left">
      <h1>Welcome back, <span><?=h(ucfirst((string)user()['role']))?></span></h1>
      <p>Together for a stronger financial future.</p>
    </div>
    <div class="ad-welcome-right">
      <a class="ad-btn-green" href="?route=members">+ New Member</a>
      <div class="ad-progress-pill">
        <small>People Savings Progress</small>
        <div class="ad-progress-bar"><i style="width:68%"></i></div>
      </div>
    </div>
  </section>

  <!-- KPI row -->
  <section class="ad-kpis">
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-blue">👥</div>
      <div>
        <span>Total Members</span>
        <b><?=number_format($members)?></b>
        <small class="up">▲ +<?=(int)$membersThisMonth?> this month</small>
      </div>
    </div>
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-green">💰</div>
      <div>
        <span>Total Deposits</span>
        <b><?=money($deposits)?></b>
        <small class="up">▲ deposits</small>
      </div>
    </div>
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-sky">🤝</div>
      <div>
        <span>Loan Portfolio</span>
        <b><?=money($loans)?></b>
        <small class="up">▲ active loans</small>
      </div>
    </div>
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-cyan">📅</div>
      <div>
        <span>Outstanding EMI</span>
        <b><?=money($outstanding)?></b>
        <small class="down">▼ pending</small>
      </div>
    </div>
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-red">⚠</div>
      <div>
        <span>Overdue EMI</span>
        <b><?=money($overdue)?></b>
        <small class="down">▲ overdue</small>
      </div>
    </div>
    <div class="ad-kpi">
      <div class="ad-kpi-icon ad-i-orange">📄</div>
      <div>
        <span>Pending Applications</span>
        <b><?=(int)$pending?></b>
        <small class="warn">Requires review</small>
      </div>
    </div>
  </section>

  <div class="ad-main-grid">
    <div class="ad-col-main">
      <!-- Financial Snapshot -->
      <section class="ad-card">
        <div class="ad-card-head">
          <h2>Financial Snapshot</h2>
          <small>Flow of funds in our cooperative</small>
        </div>
        <div class="ad-flow">
          <div class="ad-flow-item">
            <div class="ad-flow-icon ad-f-green">👥</div>
            <span>Contribution</span>
            <b><?=money($totalContribution)?></b>
          </div>
          <div class="ad-flow-arrow">›</div>
          <div class="ad-flow-item">
            <div class="ad-flow-icon ad-f-blue">₹</div>
            <span>Loans</span>
            <b><?=money($loans)?></b>
          </div>
          <div class="ad-flow-arrow">›</div>
          <div class="ad-flow-item">
            <div class="ad-flow-icon ad-f-orange">⟳</div>
            <span>EMI Recovery</span>
            <b><?=money($emiCashReceived)?></b>
          </div>
          <div class="ad-flow-arrow">›</div>
          <div class="ad-flow-item">
            <div class="ad-flow-icon ad-f-teal">▤</div>
            <span>Available Fund</span>
            <b><?=money($availableFund)?></b>
          </div>
        </div>
      </section>

      <!-- Collection Overview -->
      <section class="ad-card">
        <div class="ad-card-head">
          <h2>Collection Overview</h2>
          <small>Monthly Collections (in ₹)</small>
        </div>
        <div class="ad-chart">
          <?php foreach($chartMonths as $cm):
            $h=max(8, (int)round(($cm['amount']/$chartMax)*160));
          ?>
          <div class="ad-bar-col">
            <div class="ad-bar-val"><?=$cm['amount']>0?number_format($cm['amount']/1000,0):'0'?></div>
            <div class="ad-bar" style="height:<?=$h?>px"></div>
            <div class="ad-bar-label"><?=h($cm['label'])?></div>
          </div>
          <?php endforeach; ?>
        </div>
      </section>
    </div>

    <div class="ad-col-side">
      <!-- Recent Activity -->
      <section class="ad-card">
        <div class="ad-card-head">
          <h2>Recent Activity</h2>
          <a href="?route=notifications">View All →</a>
        </div>
        <div class="ad-activity-list" style="/* v209-final */">
          <?php if($adminActivity): foreach($adminActivity as $act):
            $icon = $act['type']==='member'?'👥':($act['type']==='contrib'?'💰':'📄');
            $st = strtolower($act['status']);
            $badgeClass = in_array($st,['completed','paid','approved','active'],true)?'ok':(in_array($st,['pending','forwarded','in review'],true)?'review':'info');
          ?>
          <div class="ad-act-row">
            <div class="ad-act-icon"><?=$icon?></div>
            <div class="ad-act-body">
              <b><?=h($act['title'])?></b>
              <small><?=$act['desc']?></small>
              <div class="ad-act-meta">
                <time><?=h(date('d M Y', strtotime((string)$act['time'])))?></time>
                <span class="ad-badge <?=$badgeClass?>"><?=h($act['status'])?></span>
              </div>
            </div>
          </div>
          <?php endforeach; else: ?>
          <div class="ad-empty">No recent activity.</div>
          <?php endif; ?>
        </div>
      </section>

      <!-- Quick Actions -->
      <section class="ad-card">
        <div class="ad-card-head"><h2>Quick Actions</h2></div>
        <div class="ad-quick">
          <a class="ad-q ad-q-green" href="?route=members">👥 Add Member</a>
          <a class="ad-q ad-q-blue" href="?route=contributions">💳 Collect Payment</a>
          <a class="ad-q ad-q-orange" href="?route=loan-applications">📄 Review Loans <?php if($pending>0):?><em><?=$pending?></em><?php endif;?></a>
          <a class="ad-q ad-q-sky" href="?route=emi-reminders">✈ Send EMI Reminder</a>
        </div>
      </section>
    </div>
  </div>
</div>
<?php $c=ob_get_clean(); layout('Dashboard',$c); exit;
}

if($route==='members'){
    requireRole(['admin','staff']);
    $msg=trim((string)($_GET['msg']??''));
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        if(($_POST['action']??'')==='upload_member_photo'){
            if(user()['role']!=='admin') exit('Admin only');
            $mid=(int)($_POST['member_id']??0);
            $ms=$db->prepare('SELECT * FROM members WHERE id=?'); $ms->bindValue(1,$mid,SQLITE3_INTEGER); $member=$ms->execute()->fetchArray(SQLITE3_ASSOC);
            if(!$member){ $msg='Member not found.'; }
            else {
                try {
                    $photo=uploadMemberFile('photo',$member['code'],'Photo');
                    if($photo==='') throw new RuntimeException('Please select a JPG, PNG or WebP photo.');
                    // Admin is never locked: Admin may replace the member photo whenever required.
                    if(!empty($member['photo'])) { $old=__DIR__.'/'.ltrim($member['photo'],'/'); if(is_file($old)) @unlink($old); }
                    $up=$db->prepare('UPDATE members SET photo=?, photo_locked=1 WHERE id=?'); $up->bindValue(1,$photo,SQLITE3_TEXT); $up->bindValue(2,$mid,SQLITE3_INTEGER); $up->execute();
                    $msg='Member photo uploaded/updated successfully. Member cannot change it, but Admin can replace it anytime.';
                } catch(Throwable $e){ $msg='Photo upload failed: '.$e->getMessage(); }
            }
        } elseif(($_POST['action']??'')==='change_address'){
            if(user()['role']!=='admin') exit('Admin only');
            $mid=(int)($_POST['member_id']??0); $address=trim((string)($_POST['address']??''));
            if($mid<=0 || $address==='') $msg='Please enter a valid member address.';
            else { $up=$db->prepare('UPDATE members SET address=? WHERE id=?'); $up->bindValue(1,$address,SQLITE3_TEXT); $up->bindValue(2,$mid,SQLITE3_INTEGER); $up->execute(); $msg='Member address updated successfully.'; }
        } elseif(($_POST['action']??'')==='change_mobile'){
            if(user()['role']!=='admin') exit('Admin only');
            $mid=(int)($_POST['member_id']??0); $mobile=preg_replace('/\D+/','',(string)($_POST['mobile']??''));
            if($mid<=0 || strlen($mobile)!==10) $msg='Please enter a valid 10-digit mobile number.';
            else { $dup=$db->prepare('SELECT id FROM members WHERE mobile=? AND id<>?'); $dup->bindValue(1,$mobile); $dup->bindValue(2,$mid,SQLITE3_INTEGER);
                if($dup->execute()->fetchArray(SQLITE3_ASSOC)) $msg='This mobile number is already registered with another member.';
                else { $up=$db->prepare('UPDATE members SET mobile=? WHERE id=?'); $up->bindValue(1,$mobile); $up->bindValue(2,$mid,SQLITE3_INTEGER); $up->execute(); $msg='Member mobile number changed successfully.'; }
            }
        } elseif(($_POST['action']??'')==='delete_member'){
            if(user()['role']!=='admin') exit('Admin only');
            $delId=(int)($_POST['member_id']??0);
            [$deleted,$deleteMsg]=deleteMemberCascade($delId);
            $msg=$deleteMsg;
        } else {
            $name=trim($_POST['name']??''); $father=trim($_POST['father_name']??''); $mobile=preg_replace('/\D+/','',$_POST['mobile']??''); $email=trim($_POST['email']??''); $address=trim($_POST['address']??'');
            $gender=trim((string)($_POST['gender']??''));
            if(!in_array($gender,['Male','Female','Other',''],true)) $gender='';
            if($name==='' || strlen($mobile)!==10) $msg='Name and valid 10-digit mobile are required.';
            else {
                $dup=$db->prepare('SELECT id,code,name FROM members WHERE mobile=? LIMIT 1');
                $dup->bindValue(1,$mobile,SQLITE3_TEXT);
                $existing=$dup->execute()->fetchArray(SQLITE3_ASSOC);
                if($existing){
                    $msg='This mobile number is already registered with Member ID '.($existing['code']??'').' ('.($existing['name']??'Member').'). Please use a different mobile number.';
                } else {
                try {
                    $next=(int)$db->querySingle("SELECT COALESCE(MAX(id),0)+1 FROM members"); $code='GS'.str_pad((string)$next,4,'0',STR_PAD_LEFT);
                    $photo=uploadMemberFile('photo',$code,'Photo'); $document=uploadMemberFile('document',$code,'Document');
                    $photoLocked = $photo !== '' ? 1 : 0;
                    $st=$db->prepare("INSERT INTO members(code,name,father_name,mobile,email,address,photo,photo_locked,document,status,gender) VALUES(?,?,?,?,?,?,?,?,?,'Active',?)");
                    $st->bindValue(1,$code);$st->bindValue(2,$name);$st->bindValue(3,$father);$st->bindValue(4,$mobile);$st->bindValue(5,$email);$st->bindValue(6,$address);$st->bindValue(7,$photo);$st->bindValue(8,$photoLocked,SQLITE3_INTEGER);$st->bindValue(9,$document);$st->bindValue(10,$gender);$st->execute(); $mid=(int)$db->lastInsertRowID();
                    // Automatically assign every member created by a Staff account to that same Staff account.
                    // This makes the new member visible in the creator's member list and enables scoped member actions.
                    $creator = user();
                    if(($creator['role']??'')==='staff' && (int)($creator['id']??0)>0){
                        $assign=$db->prepare('INSERT OR IGNORE INTO staff_member_assignments(staff_id,member_id,assigned_by) VALUES(?,?,?)');
                        $creatorId=(int)$creator['id'];
                        $assign->bindValue(1,$creatorId,SQLITE3_INTEGER);
                        $assign->bindValue(2,$mid,SQLITE3_INTEGER);
                        $assign->bindValue(3,$creatorId,SQLITE3_INTEGER);
                        $assign->execute();
                    }
                    // Generate a temporary portal password for the new member. It is stored only as a hash.
                    $tempPassword = $mobile;
                    $u=$db->prepare("INSERT INTO users(username,password_hash,role,member_id) VALUES(?,?,?,?)");$u->bindValue(1,$code);$u->bindValue(2,password_hash($tempPassword,PASSWORD_DEFAULT));$u->bindValue(3,'member');$u->bindValue(4,$mid);$u->execute();
                    $baseUrl=((!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS'])!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost');
                    $appDownloadUrl=trim(getSetting('app_download_url',''));
                    if($appDownloadUrl==='') $appDownloadUrl=$baseUrl.'/app.apk';
                    $waMsg = "नमस्कार {$name} जी, 🙏\nGS Suraha Sahyog Samiti में आपका Member Account सफलतापूर्वक बनाया गया है।\n\n👤 Member ID: {$code}\n🔐 Login ID: {$code}\n📱 Password: {$tempPassword}\n\n📲 App Download: {$appDownloadUrl}\n🌐 Website Login: {$baseUrl}\n\nApp download करके Member ID से login करें।\n🔒 सुरक्षा के लिए पहली Login के बाद Password बदल लें।\n\nधन्यवाद 🙏\nGS Suraha Sahyog Samiti\n_आपकी बचत, हमारा विश्वास_";
                    // Keep the original member-creation WhatsApp behaviour: send the complete welcome message directly.
                    // This restores the earlier flow instead of requiring the new member_welcome_credentials template.
                    $waResult = getSetting('whatsapp_auto_welcome_enabled','1')==='1' ? whatsappSendTextToMember(['id'=>$mid,'name'=>$name,'mobile'=>$mobile],$waMsg) : [true,'Welcome WhatsApp automation is OFF.'];
                    // Redirect after a successful POST so browser refresh cannot submit the same member form again.
                    $createdMsg = $waResult[0]
                        ? "Member created successfully. Login ID: $code. Mobile number को Password के रूप में WhatsApp पर भेज दिया गया।"
                        : "Member created. Login ID: $code / Password: $tempPassword. WhatsApp message नहीं भेजा जा सका: ".$waResult[1];
                    header('Location: ?route=members&created=1&msg='.rawurlencode($createdMsg));
                    exit;
                } catch (Throwable $e) { $msg=$e->getMessage(); }
                }
            }
        }
    }
    // Modern Member List filters + stats
    $search = trim((string)($_GET['q'] ?? ''));
    $filterStatus = trim((string)($_GET['status'] ?? ''));
    $filterGender = trim((string)($_GET['gender'] ?? ''));
    $filterStaff = (int)($_GET['staff'] ?? 0);
    $u = user();
    $sql = "SELECT m.*, COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) AS total_deposit FROM members m WHERE (m.name LIKE ? OR m.code LIKE ? OR m.mobile LIKE ?)";
    $like = '%'.$search.'%';
    $params = [$like, $like, $like];
    if (($u['role'] ?? '') === 'staff') {
        $sql .= ' AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id=?)';
        $params[] = (int)$u['id'];
    } elseif ($filterStaff > 0) {
        $sql .= ' AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id=?)';
        $params[] = $filterStaff;
    }
    if ($filterStatus !== '' && in_array($filterStatus, ['Active','Inactive','Closed'], true)) {
        $sql .= ' AND m.status = ?';
        $params[] = $filterStatus;
    }
    if ($filterGender !== '' && in_array($filterGender, ['Male','Female','Other'], true)) {
        $sql .= ' AND m.gender = ?';
        $params[] = $filterGender;
    }
    $sql .= ' ORDER BY m.id DESC';
    $st = $db->prepare($sql);
    foreach ($params as $i => $v) {
        $st->bindValue($i + 1, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
    }
    $list = $st->execute();

    // Stats (scoped for staff)
    $staffScopeSql = '';
    if (($u['role'] ?? '') === 'staff') {
        $staffScopeSql = ' AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id='.(int)$u['id'].')';
    }
    $totalMembers = (int)$db->querySingle("SELECT COUNT(*) FROM members m WHERE 1=1".$staffScopeSql);
    $activeMembers = (int)$db->querySingle("SELECT COUNT(*) FROM members m WHERE m.status='Active'".$staffScopeSql);
    $inactiveMembers = (int)$db->querySingle("SELECT COUNT(*) FROM members m WHERE m.status!='Active'".$staffScopeSql);
    $totalContribution = (float)$db->querySingle("SELECT COALESCE(SUM(c.amount),0) FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Paid'".$staffScopeSql);

    // Staff list for filter dropdown
    $staffOptions = [];
    $staffRes = $db->query("SELECT id, COALESCE(NULLIF(display_name,''), username) AS label FROM users WHERE role='staff' ORDER BY label");
    while ($s = $staffRes->fetchArray(SQLITE3_ASSOC)) {
        $staffOptions[] = $s;
    }

    // Collect rows so we can count + render
    $rows = [];
    while ($r = $list->fetchArray(SQLITE3_ASSOC)) {
        $rows[] = $r;
    }
    $rowCount = count($rows);

    ob_start(); ?>
    <?php if (!empty($msg)): ?><div class="alert success"><?=h($msg)?></div><?php endif; ?>

    <div class="ml-page">
      <!-- Header bar -->
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">👥</div>
          <div>
            <h1>Member List</h1>
            <p>All Registered Members</p>
          </div>
        </div>
        <button type="button" class="ml-btn-add" id="mlOpenAddMember" onclick="mlOpenAdd()">+ Add Member</button>
      </div>

      <!-- Filters -->
      <form class="ml-filters" method="get" action="">
        <input type="hidden" name="route" value="members">
        <div class="ml-search-wrap">
          <span class="ml-search-icon">🔍</span>
          <input type="search" name="q" value="<?=h($search)?>" placeholder="Member ID, Name or Mobile" aria-label="Search members">
        </div>
        <button type="submit" class="ml-btn-search">Search</button>
        <select name="status" onchange="this.form.submit()">
          <option value="">All Status</option>
          <option value="Active" <?= $filterStatus==='Active'?'selected':'' ?>>Active</option>
          <option value="Inactive" <?= $filterStatus==='Inactive'?'selected':'' ?>>Inactive</option>
          <option value="Closed" <?= $filterStatus==='Closed'?'selected':'' ?>>Closed</option>
        </select>
        <select name="gender" onchange="this.form.submit()">
          <option value="">All Gender</option>
          <option value="Male" <?= $filterGender==='Male'?'selected':'' ?>>Male</option>
          <option value="Female" <?= $filterGender==='Female'?'selected':'' ?>>Female</option>
          <option value="Other" <?= $filterGender==='Other'?'selected':'' ?>>Other</option>
        </select>
        <?php if (($u['role'] ?? '') === 'admin'): ?>
        <select name="staff" onchange="this.form.submit()">
          <option value="0">All Staff</option>
          <?php foreach ($staffOptions as $so): ?>
            <option value="<?= (int)$so['id'] ?>" <?= $filterStaff===(int)$so['id']?'selected':'' ?>><?=h($so['label'])?></option>
          <?php endforeach; ?>
        </select>
        <?php endif; ?>
        <a class="ml-btn-export" href="?route=member-excel<?= $search!=='' ? '&q='.rawurlencode($search) : '' ?>">⬇ Export Excel</a>
      </form>

      <!-- Stats -->
      <div class="ml-stats">
        <div class="ml-stat blue">
          <div class="ml-stat-icon">👥</div>
          <div>
            <span>Total Members</span>
            <b><?= number_format($totalMembers) ?></b>
          </div>
        </div>
        <div class="ml-stat green">
          <div class="ml-stat-icon">✓</div>
          <div>
            <span>Active Members</span>
            <b><?= number_format($activeMembers) ?></b>
          </div>
        </div>
        <div class="ml-stat orange">
          <div class="ml-stat-icon">⏸</div>
          <div>
            <span>Inactive Members</span>
            <b><?= number_format($inactiveMembers) ?></b>
          </div>
        </div>
        <div class="ml-stat purple">
          <div class="ml-stat-icon">👑</div>
          <div>
            <span>Total Contribution</span>
            <b>₹<?= number_format($totalContribution, 0) ?></b>
          </div>
        </div>
      </div>

      <!-- Table -->
      <div class="ml-table-card">
        <div class="table-wrap">
          <table class="ml-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Photo</th>
                <th>Member ID</th>
                <th>Name</th>
                <th>Mobile</th>
                <th>Gender</th>
                <th>Status</th>
                <th>Joined On</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php if ($rowCount === 0): ?>
                <tr><td colspan="9" class="ml-empty">No members found.</td></tr>
              <?php else: $i=1; foreach ($rows as $r):
                $photoUrl = !empty($r['photo']) ? memberFileUrl($r['photo']) : '';
                $gender = trim((string)($r['gender'] ?? ''));
                $status = trim((string)($r['status'] ?? 'Active'));
                $joined = !empty($r['created_at']) ? date('d-m-Y', strtotime($r['created_at'])) : '—';
              ?>
              <tr>
                <td><?= $i++ ?></td>
                <td>
                  <?php if ($photoUrl): ?>
                    <img class="ml-photo" src="<?= $photoUrl ?>" alt="">
                  <?php else: ?>
                    <div class="ml-photo placeholder">👤</div>
                  <?php endif; ?>
                </td>
                <td><span class="ml-code"><?= h($r['code']) ?></span></td>
                <td><b><?= h($r['name']) ?></b></td>
                <td><?= h($r['mobile'] ?: '—') ?></td>
                <td>
                  <?php if ($gender === 'Female'): ?>
                    <span class="ml-gender female">Female</span>
                  <?php elseif ($gender === 'Male'): ?>
                    <span class="ml-gender male">Male</span>
                  <?php elseif ($gender !== ''): ?>
                    <span class="ml-gender other"><?= h($gender) ?></span>
                  <?php else: ?>
                    <span class="ml-gender">—</span>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if ($status === 'Active'): ?>
                    <span class="ml-status active">✓ Active</span>
                  <?php elseif ($status === 'Closed'): ?>
                    <span class="ml-status closed">Closed</span>
                  <?php else: ?>
                    <span class="ml-status inactive">Inactive</span>
                  <?php endif; ?>
                </td>
                <td><?= h($joined) ?></td>
                <td class="ml-actions">
                  <a class="ml-act view" href="?route=member-view&id=<?= (int)$r['id'] ?>" title="View">👁 View</a>
                  <a class="ml-act edit" href="?route=member-edit&id=<?= (int)$r['id'] ?>" title="Edit">✎ Edit</a>
                  <?php if (($u['role'] ?? '') === 'admin'): ?>
                  <a class="ml-act delete" href="?route=member-view&id=<?= (int)$r['id'] ?>&delete=1" onclick="return confirm('Delete this member?')" title="Delete">🗑 Delete</a>
                  <?php endif; ?>
                </td>
              </tr>
              <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
        <div class="ml-footer">
          <span>Showing 1 to <?= $rowCount ?> of <?= $rowCount ?> members</span>
          <div class="ml-pager">
            <button type="button" disabled>Previous</button>
            <button type="button" class="active">1</button>
            <button type="button" disabled>Next</button>
          </div>
        </div>
      </div>

      <!-- Add Member Modal (same page, desktop + mobile) -->
      <div class="ml-modal-backdrop" id="mlAddBackdrop" onclick="mlCloseAdd()"></div>
      <div class="ml-modal" id="mlAddModal" role="dialog" aria-modal="true" aria-labelledby="mlAddTitle">
        <div class="ml-modal-head">
          <div>
            <h2 id="mlAddTitle">Add Member</h2>
            <p>New member create karein · Member List ke andar</p>
          </div>
          <button type="button" class="ml-modal-close" onclick="mlCloseAdd()" aria-label="Close">×</button>
        </div>
        <form method="post" enctype="multipart/form-data" class="ml-modal-body">
          <input type="hidden" name="csrf" value="<?=h(csrf())?>">
          <div class="ml-form-grid">
            <div>
              <label>Name / नाम <span class="req">*</span></label>
              <input name="name" required placeholder="Full name" autocomplete="name">
            </div>
            <div>
              <label>Father Name / पिता का नाम</label>
              <input name="father_name" placeholder="Father / Guardian name">
            </div>
            <div>
              <label>Mobile <span class="req">*</span></label>
              <input name="mobile" maxlength="10" inputmode="numeric" pattern="[0-9]{10}" required placeholder="10-digit mobile">
            </div>
            <div>
              <label>Email</label>
              <input name="email" type="email" placeholder="email@example.com">
            </div>
            <div>
              <label>Gender</label>
              <select name="gender">
                <option value="">Select</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div>
              <label>Address</label>
              <textarea name="address" placeholder="Full address" rows="2"></textarea>
            </div>
          </div>
          <div class="ml-form-section">Documents / दस्तावेज़</div>
          <div class="ml-form-grid">
            <div>
              <label>Member Photo <small>(JPG/PNG/WebP, max 5MB)</small></label>
              <input name="photo" type="file" accept="image/jpeg,image/png,image/webp">
            </div>
            <div>
              <label>Member Document <small>(PDF/JPG/PNG/WebP, max 5MB)</small></label>
              <input name="document" type="file" accept="application/pdf,image/jpeg,image/png,image/webp">
            </div>
          </div>
          <div class="ml-modal-foot">
            <button type="button" class="ml-btn-cancel" onclick="mlCloseAdd()">Cancel</button>
            <button class="ml-btn-submit" type="submit">Create Member</button>
          </div>
        </form>
      </div>
    </div>
    <script>
    (function(){
      function openAdd(){
        document.getElementById('mlAddBackdrop').classList.add('show');
        document.getElementById('mlAddModal').classList.add('show');
        document.body.classList.add('ml-modal-open');
        var n=document.querySelector('#mlAddModal input[name="name"]');
        if(n) setTimeout(function(){ n.focus(); }, 80);
      }
      function closeAdd(){
        document.getElementById('mlAddBackdrop').classList.remove('show');
        document.getElementById('mlAddModal').classList.remove('show');
        document.body.classList.remove('ml-modal-open');
      }
      window.mlOpenAdd=openAdd;
      window.mlCloseAdd=closeAdd;
      document.addEventListener('keydown', function(e){
        if(e.key==='Escape') closeAdd();
      });
      // Re-open modal if there was a validation error message after POST
      <?php if(!empty($msg) && stripos((string)$msg,'created')===false && stripos((string)$msg,'success')===false): ?>
      openAdd();
      <?php endif; ?>
    })();
    </script>
    <?php $c=ob_get_clean(); layout('Members',$c); exit;
}


function gsMemberExitInterestShare($db, int $memberId, string $method): float {
    $pool = (float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections");
    $reservePercent = max(0.0, min(100.0, (float)getSetting('profit_reserve_percent','10')));
    $pool = round($pool * (100.0 - $reservePercent) / 100.0, 2);
    $alreadyRefundedInterest = (float)$db->querySingle("SELECT COALESCE(SUM(member_interest),0) FROM member_closures WHERE status='Approved'");
    $pool = max(0.0, $pool - $alreadyRefundedInterest);
    if ($pool <= 0) return 0.0;
    $rows = $db->query("SELECT c.member_id,c.amount,c.created_at FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Paid' AND m.status='Active'");
    $memberBasis = 0.0; $totalBasis = 0.0; $today = new DateTimeImmutable('today');
    while ($r = $rows->fetchArray(SQLITE3_ASSOC)) {
        $amount = max(0.0, (float)$r['amount']);
        if ($amount <= 0) continue;
        if ($method === 'B') {
            try { $paidAt = new DateTimeImmutable(substr((string)$r['created_at'], 0, 10)); }
            catch (Throwable $e) { $paidAt = $today; }
            $months = max(1, ((int)$today->format('Y') - (int)$paidAt->format('Y')) * 12 + ((int)$today->format('n') - (int)$paidAt->format('n')) + 1);
            $basis = $amount * $months;
        } else { $basis = $amount; }
        $totalBasis += $basis;
        if ((int)$r['member_id'] === $memberId) $memberBasis += $basis;
    }
    return $totalBasis > 0 ? round($pool * $memberBasis / $totalBasis, 2) : 0.0;
}

if($route==='member-close'){
    requireRole(['admin','staff']);
    $id=(int)($_GET['id']??0);
    $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$m) exit('Member not found');
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        if(user()['role']!=='admin') exit('Admin only');
        try{
            $pendingQ=$db->prepare("SELECT * FROM member_closures WHERE member_id=? AND status='Pending' ORDER BY id DESC LIMIT 1"); $pendingQ->bindValue(1,$id,SQLITE3_INTEGER); $pendingRow=$pendingQ->execute()->fetchArray(SQLITE3_ASSOC);
            $action=(string)($_POST['closure_action']??'create');
            $contrib=(float)$db->querySingle('SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id='.(int)$id.' AND status=\'Paid\'');
            $pool=(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections");
            $exitMethod=(string)getSetting('member_exit_interest_method','A'); $memberInterest=gsMemberExitInterestShare($db,(int)$id,$exitMethod);
            $deduction=max(0,(float)($_POST['deductions']??0));
            if($contrib<=0) throw new RuntimeException('This member has no paid contribution balance.');
            $refund=round($contrib+$memberInterest-$deduction,2);
            if($refund<0) throw new RuntimeException('Refund amount cannot be negative.');
            $reason=trim((string)($_POST['reason']??''));
            $db->exec('BEGIN IMMEDIATE');
            if($action==='approve' && $pendingRow){
                $deduction=max(0,(float)($_POST['deductions']??$pendingRow['deductions']??0));$refund=round($contrib+$memberInterest-$deduction,2);
                $q=$db->prepare("UPDATE member_closures SET contribution_total=?,interest_pool=?,member_interest=?,deductions=?,refund_amount=?,reason=?,status='Approved',approved_by=? WHERE id=? AND status='Pending'");$q->bindValue(1,$contrib);$q->bindValue(2,$pool);$q->bindValue(3,$memberInterest);$q->bindValue(4,$deduction);$q->bindValue(5,$refund);$q->bindValue(6,$reason!==''?$reason:(string)$pendingRow['reason']);$q->bindValue(7,(int)user()['id'],SQLITE3_INTEGER);$q->bindValue(8,(int)$pendingRow['id'],SQLITE3_INTEGER);$q->execute();
                $up=$db->prepare("UPDATE members SET status='Closed' WHERE id=?"); $up->bindValue(1,$id,SQLITE3_INTEGER); $up->execute();
                $db->exec('COMMIT'); $waClosure=getSetting('whatsapp_auto_refund_enabled','1')==='1' ? whatsappSendTextToMember(['id'=>$id,'name'=>$m['name'],'mobile'=>$m['mobile'],'code'=>$m['code']],whatsappAutoTextForEvent(['name'=>$m['name'],'code'=>$m['code']],'closure',['amount'=>number_format($refund,2)])) : [true,'Refund WhatsApp automation is OFF.']; $msg='Pending closure approved. Final refund: '.money($refund).'.'.(!$waClosure[0]?' WhatsApp confirmation नहीं भेजा जा सका: '.$waClosure[1]:' WhatsApp confirmation sent.');
            } else {
                $q=$db->prepare("INSERT INTO member_closures(member_id,contribution_total,interest_pool,member_interest,deductions,refund_amount,reason,status,approved_by) VALUES(?,?,?,?,?,?,?,?,?)");
                foreach([1=>$id,2=>$contrib,3=>$pool,4=>$memberInterest,5=>$deduction,6=>$refund,7=>$reason,8=>'Approved',9=>(int)user()['id']] as $k=>$v){ $q->bindValue($k,$v, is_int($v)?SQLITE3_INTEGER:SQLITE3_TEXT); }
                $q->execute(); $up=$db->prepare("UPDATE members SET status='Closed' WHERE id=?"); $up->bindValue(1,$id,SQLITE3_INTEGER); $up->execute(); $db->exec('COMMIT');
                $msg='Member closed. Final refund: '.money($refund).' (contribution '.money($contrib).' + proportionate interest '.money($memberInterest).' - deductions '.money($deduction).').';
            }
        }catch(Throwable $e){ $db->exec('ROLLBACK'); $msg=$e->getMessage(); $msgType='danger'; }
    }
    $contrib=(float)$db->querySingle('SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id='.(int)$id." AND status='Paid'");
    $pool=(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections");
    $exitMethod=(string)getSetting('member_exit_interest_method','A'); $interest=gsMemberExitInterestShare($db,(int)$id,$exitMethod);$refund=round($contrib+$interest,2);
    $existing=$db->prepare('SELECT * FROM member_closures WHERE member_id=? ORDER BY id DESC LIMIT 1'); $existing->bindValue(1,$id,SQLITE3_INTEGER); $existing=$existing->execute()->fetchArray(SQLITE3_ASSOC);
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">MEMBER CLOSURE / REFUND</div><h1>Close Member Account</h1><p>Verified loan EMI से इस Member के ledger में जमा ब्याज सहित final refund देखें.</p></div><a class="btn" href="?route=members">← Members</a></div>
    <?php if($msg): ?><div class="alert <?=($msgType==='danger'?'danger':'success')?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-3">
      <div class="panel"><div class="panel-head"><h2>Member</h2><span class="badge <?=($m['status']==='Closed'?'warning':'success')?>"><?=h($m['status'])?></span></div><h2><?=h($m['name'])?></h2><p class="muted">Member ID: <?=h($m['code'])?></p><p><?=h($m['mobile'])?></p></div>
      <div class="panel"><h2>Interest Ledger</h2><div class="statline"><span>Loan interest collected</span><b><?=money($pool)?></b></div><div class="statline"><span>This member interest credited</span><b><?=money($interest)?></b></div><p class="muted">लागू तरीका <?=($exitMethod==='B'?'B — जमा राशि × समिति में रहने के महीने':'A — कुल जमा राशि के अनुपात में')?> है। हिस्सा उपलब्ध वसूले गए लोन-ब्याज पूल और पहले से मंज़ूर ब्याज रिफंड को ध्यान में रखकर निकाला जाता है।</p></div>
      <div class="panel"><h2>Expected Refund</h2><div class="kpi green"><span>Final refund before deductions</span><b><?=money($refund)?></b></div><small class="muted">Formula: Paid contribution + selected A/B method से निकला ब्याज हिस्सा − deductions.</small></div>
    </div>
    <?php if($existing): ?><div class="alert info">This member already has a closure record: Refund <?=money((float)$existing['refund_amount'])?> · <?=h($existing['created_at'])?></div><?php endif; ?>
    <?php if(user()['role']==='admin' && $m['status']!=='Closed'): ?><div class="panel"><div class="panel-head"><h2><?=($existing && ($existing['status']??'')==='Pending')?'Approve Pending Closure & Refund':'Approve Closure & Refund'?></h2><span class="badge warning">Admin Only</span></div><form method="post" class="settings-grid" onsubmit="return confirm('Member account close karke final refund record create/approve karna hai?');"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="closure_action" value="<?=($existing && ($existing['status']??'')==='Pending')?'approve':'create'?>"><div><label>Member Interest Earned</label><p><strong><?=money($interest)?></strong> · verified loan EMI interest credited</p></div><div><label>Deductions / Charges (₹)</label><input name="deductions" type="number" step="0.01" min="0" value="<?=h((string)($existing['deductions']??0))?>"></div><div class="span2"><label>Closure Reason</label><textarea name="reason" rows="3" placeholder="Member requested account closure..."><?=h((string)($existing['reason']??''))?></textarea></div><div class="span2"><button class="btn danger">🔒 <?=($existing && ($existing['status']??'')==='Pending')?'Approve & Close Member':'Close Member & Record Refund'?></button></div></form></div><?php endif; ?>
    <?php $c=ob_get_clean(); layout('Member Closure',$c); exit;
}

if($route==='member-edit'){
    requireRole(['admin','staff']);
    $id=(int)($_GET['id']??0); $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC); if(!$m) exit('Member not found');
    // Staff may modify only members explicitly assigned to their staff account.
    if((user()['role']??'')==='staff'){
        $scope=$db->prepare('SELECT 1 FROM staff_member_assignments WHERE staff_id=? AND member_id=? LIMIT 1');
        $scope->bindValue(1,(int)user()['id'],SQLITE3_INTEGER); $scope->bindValue(2,$id,SQLITE3_INTEGER);
        if(!$scope->execute()->fetchArray(SQLITE3_ASSOC)){ http_response_code(403); exit('Access denied: this member is not assigned to your staff account. / यह सदस्य आपके Staff ID से assigned नहीं है।'); }
    }
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        try{
            $name=trim((string)($_POST['name']??'')); $father=trim((string)($_POST['father_name']??''));
            $mobile=preg_replace('/\D+/','',(string)($_POST['mobile']??'')); $email=trim((string)($_POST['email']??'')); $address=trim((string)($_POST['address']??''));
            $gender=trim((string)($_POST['gender']??'')); if(!in_array($gender,['Male','Female','Other',''],true)) $gender='';
            $memberStatus=(string)($m['status']??''); if((user()['role']??'')==='admin' && isset($_POST['member_status'])) $memberStatus=trim((string)$_POST['member_status']);
            if((user()['role']??'')==='admin' && !in_array($memberStatus,['Active','Inactive'],true)) throw new RuntimeException('Please choose Active or Inactive status.');
            if($name==='') throw new RuntimeException('Name is required.');
            if(strlen($mobile)!==10) throw new RuntimeException('Please enter a valid 10-digit mobile number.');
            $dup=$db->prepare('SELECT id FROM members WHERE mobile=? AND id<>?'); $dup->bindValue(1,$mobile); $dup->bindValue(2,$id,SQLITE3_INTEGER); if($dup->execute()->fetchArray(SQLITE3_ASSOC)) throw new RuntimeException('This mobile number is already registered with another member.');
            $photo=$m['photo']??'';
            $signature=$m['signature']??'';
            $photoLocked=!empty($m['photo_locked']);
            $signatureLocked=!empty($m['signature_locked']);
            $canManagePhoto=in_array((string)(user()['role']??''),['admin','staff'],true);

            // Explicit unlock actions (separate POST buttons)
            if($canManagePhoto && (string)($_POST['unlock_action']??'')==='photo'){
                $u2=$db->prepare('UPDATE members SET photo_locked=0 WHERE id=?');
                $u2->bindValue(1,$id,SQLITE3_INTEGER); $u2->execute();
                $photoLocked=false; $m['photo_locked']=0;
                $msg='Photo unlocked. Member / Admin ab photo update कर सकते हैं।';
                $m['name']=trim((string)($_POST['name']??$m['name']));
                // skip rest of profile save for pure unlock
                throw new RuntimeException('__UNLOCK_OK__PHOTO__');
            }
            if($canManagePhoto && (string)($_POST['unlock_action']??'')==='signature'){
                $u2=$db->prepare('UPDATE members SET signature_locked=0 WHERE id=?');
                $u2->bindValue(1,$id,SQLITE3_INTEGER); $u2->execute();
                $signatureLocked=false; $m['signature_locked']=0;
                throw new RuntimeException('__UNLOCK_OK__SIGNATURE__');
            }
            if($canManagePhoto && (string)($_POST['unlock_action']??'')==='both'){
                $u2=$db->prepare('UPDATE members SET photo_locked=0, signature_locked=0 WHERE id=?');
                $u2->bindValue(1,$id,SQLITE3_INTEGER); $u2->execute();
                $photoLocked=false; $signatureLocked=false; $m['photo_locked']=0; $m['signature_locked']=0;
                throw new RuntimeException('__UNLOCK_OK__BOTH__');
            }

            // Checkbox unlock during Save
            if($canManagePhoto && !empty($_POST['unlock_photo'])){ $photoLocked=false; }
            if($canManagePhoto && !empty($_POST['unlock_signature'])){ $signatureLocked=false; }

            if(isset($_FILES['photo']) && ($_FILES['photo']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE){
                if(!$canManagePhoto && $photoLocked) throw new RuntimeException('Member photo is locked. Admin/Staff unlock करके replace कर सकते हैं।');
                if($photoLocked && $canManagePhoto && empty($_POST['unlock_photo'])) throw new RuntimeException('Photo locked है। पहले Unlock Photo चुनें, फिर नई photo upload करें।');
                $newPhoto=uploadMemberFile('photo',$m['code'],'Photo');
                if($newPhoto==='') throw new RuntimeException('Please select a JPG, PNG or WebP photo.');
                if(!empty($photo)) { $old=__DIR__.'/'.ltrim($photo,'/'); if(is_file($old)) @unlink($old); }
                $photo=$newPhoto; $photoLocked=true;
            }
            if(isset($_FILES['signature']) && ($_FILES['signature']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE){
                if(!$canManagePhoto && $signatureLocked) throw new RuntimeException('Signature locked है। Admin/Staff unlock करें।');
                if($signatureLocked && $canManagePhoto && empty($_POST['unlock_signature'])) throw new RuntimeException('Signature locked है। पहले Unlock Signature चुनें।');
                $tmp=$_FILES['signature']['tmp_name']; $sigTmp=__DIR__.'/uploads/signatures/'.preg_replace('/[^A-Za-z0-9_-]+/','_',$m['code']).'_member_edit_'.bin2hex(random_bytes(5));
                if(!is_dir(dirname($sigTmp))) @mkdir(dirname($sigTmp),0775,true);
                $mime=(new finfo(FILEINFO_MIME_TYPE))->file($tmp); $ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'][$mime]??''; if(!$ext) throw new RuntimeException('Member signature must be JPG, PNG or WebP.');
                $src=$sigTmp.'.'.$ext; if(!move_uploaded_file($tmp,$src)) throw new RuntimeException('Could not save signature.'); $out=$sigTmp.'_transparent.png'; if(makeSignatureTransparent($src,$out)) { @unlink($src); $signature=str_replace(__DIR__.'/','',$out); } else { $signature=str_replace(__DIR__.'/','',$src); }
                if(!empty($m['signature'])){ $oldPath=__DIR__.'/'.ltrim($m['signature'],'/'); if(is_file($oldPath)) @unlink($oldPath); }
                $signatureLocked=true;
            }
            $up=$db->prepare('UPDATE members SET name=?,father_name=?,mobile=?,email=?,address=?,photo=?,photo_locked=?,signature=?,signature_locked=?,status=?,gender=? WHERE id=?');
            foreach([$name,$father,$mobile,$email,$address,$photo,$photoLocked?1:0,$signature,$signatureLocked?1:0,$memberStatus,$gender] as $i=>$v) $up->bindValue($i+1,$v,is_int($v)?SQLITE3_INTEGER:SQLITE3_TEXT); $up->bindValue(12,$id,SQLITE3_INTEGER); $up->execute();
            $m['name']=$name;$m['father_name']=$father;$m['mobile']=$mobile;$m['email']=$email;$m['address']=$address;$m['photo']=$photo;$m['photo_locked']=$photoLocked?1:0;$m['signature']=$signature;$m['signature_locked']=$signatureLocked?1:0;$m['status']=$memberStatus;$m['gender']=$gender;
            $msg='Member details updated successfully. / सदस्य की सभी जानकारी अपडेट हो गई।';
        }catch(Throwable $e){
            $em=$e->getMessage();
            if($em==='__UNLOCK_OK__PHOTO__'){ $msg='Photo unlocked. Member My Profile se update kar sakta hai.'; $msgType='success'; }
            elseif($em==='__UNLOCK_OK__SIGNATURE__'){ $msg='Signature unlocked. Member My Profile se update kar sakta hai.'; $msgType='success'; }
            elseif($em==='__UNLOCK_OK__BOTH__'){ $msg='Photo + Signature unlocked. Member update kar sakta hai.'; $msgType='success'; }
            else { $msg=$em; $msgType='danger'; }
        }
    }
    // refresh member row so lock flags show correctly
    $stR=$db->prepare('SELECT * FROM members WHERE id=?'); $stR->bindValue(1,$id,SQLITE3_INTEGER); $mR=$stR->execute()->fetchArray(SQLITE3_ASSOC); if($mR) $m=$mR;
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">MEMBER MODIFY</div><h1>Modify Details / विवरण बदलें</h1><p>Name, photo, father name, signature, mobile, email and address एक ही जगह बदलें।</p></div><a class="btn" href="?route=members">← Members</a></div>
    <?php if($msg): ?><div class="alert <?=$msgType==='danger'?'danger':'success'?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-2"><div class="panel"><h2>Member Details</h2><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>">
      <label>Name / नाम</label><input name="name" value="<?=h($m['name'])?>" required>
      <label>Father Name / पिता का नाम</label><input name="father_name" value="<?=h($m['father_name']??'')?>">
      <label>Mobile / मोबाइल</label><input name="mobile" maxlength="10" value="<?=h($m['mobile'])?>" required>
      <label>Email / ईमेल</label><input name="email" type="email" value="<?=h($m['email']??'')?>">
      <label>Gender</label>
      <select name="gender">
        <option value="">Select</option>
        <option value="Male" <?= (($m['gender']??'')==='Male')?'selected':'' ?>>Male</option>
        <option value="Female" <?= (($m['gender']??'')==='Female')?'selected':'' ?>>Female</option>
        <option value="Other" <?= (($m['gender']??'')==='Other')?'selected':'' ?>>Other</option>
      </select>
      <label>Address / पता</label><textarea name="address"><?=h($m['address']??'')?></textarea>
      <?php if(user()['role']==='admin'): ?><label>Member Status</label><select name="member_status"><option value="Active" <?=((string)($m['status']??'')==='Active')?'selected':''?>>Active</option><option value="Inactive" <?=((string)($m['status']??'')==='Inactive')?'selected':''?>>Inactive</option></select><small class="muted">Active members can use services allowed to active accounts. Staff cannot change this status.</small><?php endif; ?>
      <div class="unlock-box" style="border:1px solid #dbe2ec;border-radius:12px;padding:12px;margin:12px 0;background:#f8fafc">
        <b style="display:block;margin-bottom:8px">Photo & Signature Lock</b>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px">
          <span class="badge <?=!empty($m['photo_locked'])?'warning':'success'?>">Photo: <?=!empty($m['photo_locked'])?'Locked':'Unlocked'?></span>
          <span class="badge <?=!empty($m['signature_locked'])?'warning':'success'?>">Signature: <?=!empty($m['signature_locked'])?'Locked':'Unlocked'?></span>
        </div>
        <?php if(in_array(user()['role'],['admin','staff'],true)): ?>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button class="btn small" type="submit" name="unlock_action" value="photo" formaction="" onclick="return confirm('Photo unlock करें?')">🔓 Unlock Photo</button>
            <button class="btn small" type="submit" name="unlock_action" value="signature" onclick="return confirm('Signature unlock करें?')">🔓 Unlock Signature</button>
            <button class="btn small" type="submit" name="unlock_action" value="both" onclick="return confirm('Photo + Signature unlock करें?')">🔓 Unlock Both</button>
          </div>
          <small class="muted" style="display:block;margin-top:8px">Unlock ke baad member My Profile se update kar sakta hai. Save se pehle checkbox bhi use kar sakte hain.</small>
        <?php else: ?>
          <small class="muted">Locked items sirf Admin/Staff unlock kar sakte hain.</small>
        <?php endif; ?>
      </div>

      <label>Member Photo / सदस्य फोटो</label>
      <?php if(in_array(user()['role'],['admin','staff'],true)): ?>
        <?php if(!empty($m['photo_locked'])): ?>
          <div class="alert info" style="margin-bottom:8px">✓ Photo locked. Unlock button upar use karein, ya checkbox tick karke save karein.</div>
          <label class="permission-option" style="display:flex;align-items:center;gap:8px;margin:8px 0">
            <input type="checkbox" name="unlock_photo" value="1"> <span>🔓 Unlock Photo on Save</span>
          </label>
        <?php else: ?>
          <div class="alert success" style="margin-bottom:8px">Photo unlocked — replace allowed.</div>
        <?php endif; ?>
        <input name="photo" type="file" accept="image/jpeg,image/png,image/webp">
      <?php elseif(!empty($m['photo_locked'])): ?>
        <div class="alert info">✓ Photo locked. Admin/Staff unlock karein.</div>
      <?php else: ?>
        <input name="photo" type="file" accept="image/jpeg,image/png,image/webp"><small class="muted">Unlocked — aap photo update kar sakte hain.</small>
      <?php endif; ?>

      <label>Member Signature / सदस्य हस्ताक्षर</label>
      <?php if(in_array(user()['role'],['admin','staff'],true)): ?>
        <?php if(!empty($m['signature_locked'])): ?>
          <div class="alert info" style="margin-bottom:8px">✓ Signature locked.</div>
          <label class="permission-option" style="display:flex;align-items:center;gap:8px;margin:8px 0">
            <input type="checkbox" name="unlock_signature" value="1"> <span>🔓 Unlock Signature on Save</span>
          </label>
        <?php else: ?>
          <div class="alert success" style="margin-bottom:8px">Signature unlocked — replace allowed.</div>
        <?php endif; ?>
        <input name="signature" type="file" accept="image/jpeg,image/png,image/webp">
        <small class="muted">New signature transparent automatically.</small>
      <?php elseif(!empty($m['signature_locked'])): ?>
        <div class="alert info">✓ Signature locked. Admin/Staff unlock karein.</div>
      <?php else: ?>
        <input name="signature" type="file" accept="image/jpeg,image/png,image/webp"><small class="muted">Unlocked — aap signature update kar sakte hain.</small>
      <?php endif; ?>

      <button class="btn primary full" style="margin-top:15px">💾 Save All Changes / सभी बदलाव सेव करें</button>
    </form></div><div class="panel"><h2>Current Photo & Signature</h2><div class="member-photo-wrap"><?php if(!empty($m['photo'])):?><img class="member-photo" src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>"><?php else:?><div class="member-photo placeholder">👤</div><?php endif; ?><div><b><?=h($m['name'])?></b><small class="block"><?=h($m['code'])?></small></div></div><?php if(!empty($m['signature'])):?><div class="signature-preview" style="margin-top:16px"><img src="<?=signatureFileUrl($m['signature'])?>" alt="Member signature"></div><?php else:?><div class="alert info" style="margin-top:16px">Member signature not uploaded.</div><?php endif; ?></div></div>
    <?php $c=ob_get_clean(); layout('Modify Member',$c); exit;
}

if($route==='admin-member-photo'){
    requireRole(['admin','staff']);
    $id=(int)($_GET['id']??0); $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC); if(!$m) exit('Member not found');
    if((user()['role']??'')==='staff'){
        $scope=$db->prepare('SELECT 1 FROM staff_member_assignments WHERE staff_id=? AND member_id=? LIMIT 1');
        $scope->bindValue(1,(int)user()['id'],SQLITE3_INTEGER); $scope->bindValue(2,$id,SQLITE3_INTEGER);
        if(!$scope->execute()->fetchArray(SQLITE3_ASSOC)){ http_response_code(403); exit('Access denied: member not assigned to your staff account.'); }
    }
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        try{
            $action=(string)($_POST['action']??'upload_member_photo');
            if($action==='unlock_photo'){
                $up=$db->prepare('UPDATE members SET photo_locked=0 WHERE id=?'); $up->bindValue(1,$id,SQLITE3_INTEGER); $up->execute();
                $m['photo_locked']=0; $msg='Photo unlocked. Member My Profile se update kar sakta hai.';
            } elseif($action==='unlock_signature'){
                $up=$db->prepare('UPDATE members SET signature_locked=0 WHERE id=?'); $up->bindValue(1,$id,SQLITE3_INTEGER); $up->execute();
                $m['signature_locked']=0; $msg='Signature unlocked. Member My Profile se update kar sakta hai.';
            } elseif($action==='unlock_both'){
                $up=$db->prepare('UPDATE members SET photo_locked=0, signature_locked=0 WHERE id=?'); $up->bindValue(1,$id,SQLITE3_INTEGER); $up->execute();
                $m['photo_locked']=0; $m['signature_locked']=0; $msg='Photo + Signature unlocked.';
            } else {
                $locked=!empty($m['photo_locked']);
                if($locked && empty($_POST['unlock_photo'])) throw new RuntimeException('Photo locked है। पहले Unlock करें।');
                $photo=uploadMemberFile('photo',$m['code'],'Photo');
                if($photo==='') throw new RuntimeException('Please select a JPG, PNG or WebP photo.');
                if(!empty($m['photo'])){ $old=__DIR__.'/'.ltrim((string)$m['photo'],'/'); if(is_file($old)) @unlink($old); }
                $up=$db->prepare('UPDATE members SET photo=?, photo_locked=1 WHERE id=?'); $up->bindValue(1,$photo,SQLITE3_TEXT); $up->bindValue(2,$id,SQLITE3_INTEGER); $up->execute();
                $m['photo']=$photo; $m['photo_locked']=1; $msg='Member photo uploaded successfully. It is now locked.';
            }
        }catch(Throwable $e){ $msg=$e->getMessage(); $msgType='danger'; }
    }
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">MEMBER PHOTO CONTROL</div><h1>Member Photo</h1><p>Admin / Staff photo unlock करके replace कर सकते हैं।</p></div><a class="btn" href="?route=member-view&id=<?=$m['id']?>">← Back to Member</a></div>
    <?php if($msg): ?><div class="alert <?=$msgType==='danger'?'danger':'success'?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-2"><div class="panel"><div class="member-photo-wrap"><?php if(!empty($m['photo'])): ?><img class="member-photo" src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>"><?php else: ?><div class="member-photo placeholder">👤</div><?php endif; ?><div><h2><?=h($m['name'])?></h2><p class="muted">Member ID: <?=h($m['code'])?></p><p><?=h($m['mobile'])?></p></div></div></div>
    <div class="panel">
      <h2><?=(!empty($m['photo_locked'])||!empty($m['photo']))?'Photo Locked / फोटो लॉक':'Upload Photo / फोटो अपलोड'?></h2>
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin:10px 0">
        <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="unlock_photo"><button class="btn" type="submit">🔓 Unlock Photo</button></form>
        <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="unlock_signature"><button class="btn" type="submit">🔓 Unlock Signature</button></form>
        <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="unlock_both"><button class="btn" type="submit">🔓 Unlock Both</button></form>
      </div>
      <div style="margin-bottom:8px">
        <span class="badge <?=!empty($m['photo_locked'])?'warning':'success'?>">Photo: <?=!empty($m['photo_locked'])?'Locked':'Unlocked'?></span>
        <span class="badge <?=!empty($m['signature_locked'])?'warning':'success'?>">Signature: <?=!empty($m['signature_locked'])?'Locked':'Unlocked'?></span>
      </div>
      <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="<?=h(csrf())?>">
        <input type="hidden" name="action" value="upload_member_photo">
        <?php if(!empty($m['photo_locked'])||!empty($m['photo'])): ?>
          <label class="permission-option" style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" name="unlock_photo" value="1"> <span>Unlock + replace together</span></label>
        <?php endif; ?>
        <label>Member Photo <small>(JPG/PNG/WebP, max 5MB)</small></label>
        <input name="photo" type="file" accept="image/jpeg,image/png,image/webp" required>
        <button class="btn primary full">📷 Upload / Replace Photo</button>
      </form>
    </div></div>
    <?php $c=ob_get_clean(); layout('Member Photo',$c); exit;
}

if($route==='admin-member-mobile'){
    requireRole(['admin']); $id=(int)($_GET['id']??0); $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC); if(!$m) exit('Member not found'); $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){ checkCsrf(); $mobile=preg_replace('/\D+/','',(string)($_POST['mobile']??'')); if(strlen($mobile)!==10){$msg='Please enter a valid 10-digit mobile number.';$msgType='danger';} else {$dup=$db->prepare('SELECT id FROM members WHERE mobile=? AND id<>?');$dup->bindValue(1,$mobile);$dup->bindValue(2,$id,SQLITE3_INTEGER);if($dup->execute()->fetchArray(SQLITE3_ASSOC)){$msg='This mobile number is already registered with another member.';$msgType='danger';}else{$up=$db->prepare('UPDATE members SET mobile=? WHERE id=?');$up->bindValue(1,$mobile);$up->bindValue(2,$id,SQLITE3_INTEGER);$up->execute();$m['mobile']=$mobile;$msg='Mobile number updated successfully.';}} }
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ADMIN MEMBER CONTROL</div><h1>Change Member Mobile</h1><p>Only Admin can change the registered mobile number. <span class="hi-sub">केवल Admin सदस्य का मोबाइल नंबर बदल सकता है।</span></p></div><a class="btn" href="?route=members">← Back to Members</a></div><?php if($msg): ?><div class="alert <?=$msgType==='danger'?'danger':'success'?>"><?=h($msg)?></div><?php endif; ?><div class="panel mobile-change-panel"><div class="member-photo-wrap"><div class="member-photo placeholder">📱</div><div><h2><?=h($m['name'])?></h2><p class="muted">Member ID: <?=h($m['code'])?></p><p>Current Mobile: <b><?=h($m['mobile'])?></b></p></div></div><form method="post" class="settings-grid" style="margin-top:18px"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><div><label>New Mobile Number / नया मोबाइल नंबर</label><input name="mobile" inputmode="numeric" maxlength="10" pattern="[0-9]{10}" value="<?=h($m['mobile'])?>" required></div><div style="align-self:end"><button class="btn primary full">📱 Update Mobile Number</button></div></form><div class="alert info" style="margin-top:14px">Member name, login ID and password are not changed here. / यहाँ सदस्य का नाम, Login ID और Password नहीं बदले जाते।</div></div><?php $c=ob_get_clean(); layout('Change Member Mobile',$c); exit;
}

if($route==='admin-member-address'){
    requireRole(['admin']);
    $id=(int)($_GET['id']??0); $st=$db->prepare('SELECT * FROM members WHERE id=?'); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC); if(!$m) exit('Member not found');
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $address=trim((string)($_POST['address']??''));
        if($address===''){ $msg='Please enter a valid address.'; $msgType='danger'; }
        else { $up=$db->prepare('UPDATE members SET address=? WHERE id=?'); $up->bindValue(1,$address,SQLITE3_TEXT); $up->bindValue(2,$id,SQLITE3_INTEGER); $up->execute(); $m['address']=$address; $msg='Member address updated successfully.'; }
    }
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">ADMIN MEMBER CONTROL</div><h1>Member Address</h1><p>Admin can update the member address. <span class="hi-sub">केवल Admin सदस्य का पता बदल सकता है।</span></p></div><a class="btn" href="?route=member-view&id=<?=$m['id']?>">← Back to Member</a></div>
    <?php if($msg): ?><div class="alert <?=$msgType==='danger'?'danger':'success'?>"><?=h($msg)?></div><?php endif; ?>
    <div class="panel" style="max-width:760px"><div class="member-photo-wrap"><div class="member-photo placeholder">📍</div><div><h2><?=h($m['name'])?></h2><p class="muted"><?=h($m['code'])?> · <?=h($m['mobile'])?></p></div></div><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><label>Address / पता</label><textarea name="address" rows="6" required><?=h($m['address'])?></textarea><div class="inline-form" style="margin-top:12px"><button class="btn primary">💾 Update Address</button><a class="btn" href="?route=member-view&id=<?=$m['id']?>">Cancel</a></div></form></div>
    <?php $c=ob_get_clean(); layout('Change Member Address',$c); exit;
}

if($route==='member-view'){
    requireRole(['admin','staff']);
    $id=(int)($_GET['id']??0);
    $st=$db->prepare("SELECT * FROM members WHERE id=?"); $st->bindValue(1,$id,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$m) exit('Member not found');

    // Staff may view only assigned members
    if((user()['role']??'')==='staff'){
        $scope=$db->prepare('SELECT 1 FROM staff_member_assignments WHERE staff_id=? AND member_id=? LIMIT 1');
        $scope->bindValue(1,(int)user()['id'],SQLITE3_INTEGER); $scope->bindValue(2,$id,SQLITE3_INTEGER);
        if(!$scope->execute()->fetchArray(SQLITE3_ASSOC)){ http_response_code(403); exit('Access denied: this member is not assigned to your staff account.'); }
    }

    // Delete is submitted from this page and uses the same cascade handler as the Member List.
    if($_SERVER['REQUEST_METHOD']==='POST' && (($_POST['action']??'')==='delete_member')){
        if(user()['role']!=='admin') exit('Admin only');
        checkCsrf();
        $delId=(int)($_POST['member_id']??0);
        if($delId !== $id) exit('Invalid member.');
        [$deleted,$deleteMsg]=deleteMemberCascade($delId);
        if($deleted){ header('Location: ?route=members&deleted=1&msg='.rawurlencode($deleteMsg)); exit; }
    }

    $total=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=$id AND status='Paid'");
    $pendingContrib=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=$id AND status!='Paid'");
    $max=$total*(float)getSetting('loan_eligibility_percent','80')/100;
    $loanCount=(int)$db->querySingle("SELECT COUNT(*) FROM loans WHERE member_id=$id");
    $activeLoans=(int)$db->querySingle("SELECT COUNT(*) FROM loans WHERE member_id=$id AND status IN ('Active','Approved','Running')");
    $loanPrincipal=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans WHERE member_id=$id");
    $paidEmi=(float)$db->querySingle("SELECT COALESCE(SUM(p.paid_amount),0) FROM payments p WHERE p.member_id=$id AND p.status='Paid'");
    $since=!empty($m['created_at']) ? date('d M Y',strtotime((string)$m['created_at'])) : '—';
    $joinedShort=!empty($m['created_at']) ? date('d-m-Y',strtotime((string)$m['created_at'])) : '—';
    $initial=strtoupper(substr(trim((string)$m['name']),0,1));
    $gender=trim((string)($m['gender']??''));
    $status=trim((string)($m['status']??'Active'));

    // Assigned staff
    $assignedStaffName='—';
    $as=$db->prepare("SELECT COALESCE(NULLIF(u.display_name,''), u.username) AS label FROM staff_member_assignments sma JOIN users u ON u.id=sma.staff_id WHERE sma.member_id=? ORDER BY sma.assigned_at DESC, sma.id DESC LIMIT 1");
    $as->bindValue(1,$id,SQLITE3_INTEGER);
    $asRow=$as->execute()->fetchArray(SQLITE3_ASSOC);
    if($asRow) $assignedStaffName=(string)$asRow['label'];

    ob_start(); ?>
    <div class="md-page">
      <!-- Top bar -->
      <div class="md-topbar">
        <a class="md-back" href="?route=members">← Members</a>
        <div class="md-topbar-actions">
          <a class="md-btn ghost" href="?route=member-id-card&id=<?=(int)$m['id']?>" target="_blank" rel="noopener">🪪 ID Card</a>
          <?php if(in_array(user()['role'],['admin','staff'],true)): ?>
          <a class="md-btn primary" href="?route=member-edit&id=<?=(int)$m['id']?>">✎ Edit Profile</a>
          <?php endif; ?>
        </div>
      </div>

      <!-- Hero -->
      <section class="md-hero">
        <div class="md-hero-left">
          <?php if(!empty($m['photo'])): ?>
            <img class="md-avatar" src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>">
          <?php else: ?>
            <div class="md-avatar placeholder"><?=h($initial)?></div>
          <?php endif; ?>
          <div class="md-identity">
            <div class="md-chips">
              <span class="md-chip member">Member</span>
              <?php if($status==='Active'): ?>
                <span class="md-chip active">✓ Active</span>
              <?php elseif($status==='Closed'): ?>
                <span class="md-chip closed">Closed</span>
              <?php else: ?>
                <span class="md-chip inactive"><?=h($status)?></span>
              <?php endif; ?>
              <?php if($gender!==''): ?>
                <span class="md-chip gender"><?=h($gender)?></span>
              <?php endif; ?>
            </div>
            <h1><?=h($m['name'])?></h1>
            <div class="md-meta">
              <span class="md-code"><?=h($m['code'])?></span>
              <span>📞 <?=h($m['mobile'])?></span>
              <?php if(!empty($m['email'])): ?><span>✉ <?=h($m['email'])?></span><?php endif; ?>
            </div>
            <div class="md-submeta">
              <span>Joined <?=h($since)?></span>
              <span>Staff: <?=h($assignedStaffName)?></span>
            </div>
          </div>
        </div>
        <div class="md-hero-deposit">
          <span>Total Deposit</span>
          <strong><?=money($total)?></strong>
          <small>Eligible loan up to <?=money($max)?></small>
        </div>
      </section>

      <!-- Quick actions -->
      <div class="md-actions">
        <a class="md-act green" href="<?=h(memberTelHref((string)$m['mobile']))?>"><span>📞</span><b>Call</b></a>
        <a class="md-act blue" target="_blank" rel="noopener" href="<?=h(memberWhatsAppHref((string)$m['mobile'],memberContactMessage($m)))?>"><span>💬</span><b>WhatsApp</b></a>
        <a class="md-act purple" href="?route=member-id-card&id=<?=(int)$m['id']?>" target="_blank" rel="noopener"><span>🪪</span><b>ID Card</b></a>
        <?php if(in_array(user()['role'],['admin','staff'],true)): ?>
        <a class="md-act amber" href="?route=member-edit&id=<?=(int)$m['id']?>"><span>✎</span><b>Modify</b></a>
        <?php endif; ?>
        <a class="md-act red" href="?route=member-close&id=<?=(int)$m['id']?>"><span>🔒</span><b>Close / Refund</b></a>
        <?php if(user()['role']==='admin'): ?>
        <form method="post" class="md-act-form" onsubmit="return confirm('Delete this member and all related records? This cannot be undone.');">
          <input type="hidden" name="csrf" value="<?=h(csrf())?>">
          <input type="hidden" name="action" value="delete_member">
          <input type="hidden" name="member_id" value="<?=(int)$m['id']?>">
          <button type="submit" class="md-act delete"><span>🗑</span><b>Delete</b></button>
        </form>
        <?php endif; ?>
      </div>

      <!-- Stats -->
      <div class="md-stats">
        <div class="md-stat blue"><div class="md-stat-icon">₹</div><div><span>Total Deposit</span><b><?=money($total)?></b></div></div>
        <div class="md-stat green"><div class="md-stat-icon">✓</div><div><span>EMI / Payments Paid</span><b><?=money($paidEmi)?></b></div></div>
        <div class="md-stat purple"><div class="md-stat-icon">📋</div><div><span>Total Loans</span><b><?=number_format($loanCount)?></b></div></div>
        <div class="md-stat orange"><div class="md-stat-icon">🏦</div><div><span>Loan Principal</span><b><?=money($loanPrincipal)?></b></div></div>
      </div>

      <!-- Two column details -->
      <div class="md-grid">
        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">👤</span><h2>Personal Details</h2></div>
          <div class="md-detail-list">
            <div><small>Member ID</small><b><?=h($m['code'])?></b></div>
            <div><small>Full Name</small><b><?=h($m['name'])?></b></div>
            <div><small>Father / Guardian</small><b><?=h($m['father_name']?:'—')?></b></div>
            <div><small>Gender</small><b><?=h($gender?:'—')?></b></div>
            <div><small>Mobile</small><b><?=h($m['mobile'])?></b></div>
            <div><small>Email</small><b><?=h($m['email']?:'—')?></b></div>
            <div><small>Status</small><b><?=h($status)?></b></div>
            <div><small>Joined On</small><b><?=h($joinedShort)?></b></div>
            <div class="wide"><small>Address</small><b><?=h($m['address']?:'—')?></b></div>
            <div class="wide"><small>Assigned Staff</small><b><?=h($assignedStaffName)?></b></div>
          </div>
        </section>

        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">💰</span><h2>Financial Summary</h2></div>
          <div class="md-detail-list">
            <div><small>Paid Contributions</small><b><?=money($total)?></b></div>
            <div><small>Pending Contributions</small><b><?=money($pendingContrib)?></b></div>
            <div><small>Loan Eligibility (<?=h(getSetting('loan_eligibility_percent','80'))?>%)</small><b><?=money($max)?></b></div>
            <div><small>Active / Total Loans</small><b><?=number_format($activeLoans)?> / <?=number_format($loanCount)?></b></div>
            <div><small>Loan Principal</small><b><?=money($loanPrincipal)?></b></div>
            <div><small>EMI / Payments Received</small><b><?=money($paidEmi)?></b></div>
          </div>
        </section>

        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">📄</span><h2>Documents & Photo</h2></div>
          <div class="md-docs">
            <?php if(!empty($m['document'])): ?>
              <a class="md-doc" href="<?=memberFileUrl($m['document'])?>" target="_blank" rel="noopener">
                <span>📄</span><div><b>Member Document</b><small>Open / Download</small></div><strong>›</strong>
              </a>
            <?php else: ?>
              <div class="md-doc empty"><span>📄</span><div><b>No document uploaded</b><small>Upload from Edit Profile</small></div></div>
            <?php endif; ?>
            <a class="md-doc secondary" href="?route=admin-member-photo&id=<?=(int)$m['id']?>">
              <span>📷</span><div><b>Member Photo</b><small><?=!empty($m['photo'])?'Photo available · Manage':'Upload photo'?></small></div><strong>›</strong>
            </a>
            <?php if(!empty($m['signature'])): ?>
              <div class="md-signature">
                <small>Signature</small>
                <img src="<?=signatureFileUrl($m['signature'])?>" alt="Signature">
              </div>
            <?php endif; ?>
          </div>
        </section>

        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">🏦</span><h2>Bank / UPI Details</h2></div>
          <div class="md-detail-list">
            <div><small>Bank Name</small><b><?=h($m['bank_name']?:'—')?></b></div>
            <div><small>Account Holder</small><b><?=h($m['account_holder']?:'—')?></b></div>
            <div><small>Account Number</small><b><?=h($m['account_number']?:'—')?></b></div>
            <div><small>IFSC</small><b><?=h($m['ifsc']?:'—')?></b></div>
            <div class="wide"><small>UPI ID</small><b><?=h($m['bank_upi_id']?:'—')?></b></div>
          </div>
        </section>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Member Details',$c); exit;
}

if($route==='contributions'){
    requireRole(['admin','staff']);
    $flashContribution = $_SESSION['contribution_flash'] ?? null;
    unset($_SESSION['contribution_flash']);
    $msg = is_array($flashContribution) ? (string)($flashContribution['msg'] ?? '') : '';
    $msgType = is_array($flashContribution) ? (string)($flashContribution['type'] ?? 'success') : 'success';
    $currentUser=user();
    $staffId=($currentUser['role']??'')==='staff'?(int)$currentUser['id']:0;
    $staffFilter=$staffId>0?" AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id=$staffId)":"";
    $staffContributionFilter=$staffId>0?" AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=c.member_id AND sma.staff_id=$staffId)":"";
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $action=(string)($_POST['action']??''); $cid=(int)($_POST['id']??0);
        if(in_array($action,['approve','reject'],true) && $cid>0){
            $st=$db->prepare("SELECT c.* FROM contributions c WHERE c.id=? AND c.status='Pending'".$staffContributionFilter." LIMIT 1");
            $st->bindValue(1,$cid,SQLITE3_INTEGER); $res=$st->execute(); $c=$res?$res->fetchArray(SQLITE3_ASSOC):false;
            if(!$c){$msg='यह Pending Contribution नहीं मिला, पहले Verify हो चुका है, या यह आपके assigned member का भुगतान नहीं है।';$msgType='warning';}
            elseif($action==='approve'){
                $st=$db->prepare("UPDATE contributions SET status='Paid' WHERE id=? AND status='Pending'");
                $st->bindValue(1,$cid,SQLITE3_INTEGER);
                if($st->execute() && $db->changes()===1){
                    $memberWa=$db->query("SELECT m.id,m.name,m.mobile,m.code FROM members m WHERE m.id=".(int)$c['member_id'])->fetchArray(SQLITE3_ASSOC); $waNote='';
                    if(getSetting('whatsapp_auto_contribution_enabled','0')==='1' && $memberWa){
                        try { $wr=whatsappSendTextToMember($memberWa,whatsappAutoTextForEvent($memberWa,'contribution',['amount'=>number_format((float)$c['amount'],2),'txn'=>$c['txn_id']]),5,2); $waNote=$wr[0]?' WhatsApp confirmation sent.':' WhatsApp सूचना: '.$wr[1]; }
                        catch (Throwable $waError) { error_log('GS Suraha contribution verify WhatsApp error: '.$waError->getMessage()); $waNote=' WhatsApp संदेश नहीं भेजा जा सका; भुगतान सत्यापन सुरक्षित है।'; }
                    }
                    $msg='Contribution payment verified successfully.'.$waNote;
                }else{$msg='Verification failed. कृपया पेज Refresh करके Status जाँचें।';$msgType='danger';}
            }else{
                $reason=trim((string)($_POST['reject_reason']??''));
                if($reason===''){$msg='Reject reason is required.';$msgType='danger';}
                else{
                    $st=$db->prepare("UPDATE contributions SET status='Rejected',reject_reason=?,rejected_by=?,rejected_at=CURRENT_TIMESTAMP WHERE id=? AND status='Pending'");
                    $st->bindValue(1,$reason,SQLITE3_TEXT);$st->bindValue(2,(int)($currentUser['id']??0),SQLITE3_INTEGER);$st->bindValue(3,$cid,SQLITE3_INTEGER);
                    if($st->execute() && $db->changes()===1){$memberWa=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$c['member_id'])->fetchArray(SQLITE3_ASSOC);$waNote='';if($memberWa){try{$wr=whatsappSendTextToMember($memberWa,whatsappAutoTextForEvent($memberWa,'contribution_rejected',['amount'=>number_format((float)$c['amount'],2),'txn'=>$c['txn_id'],'reason'=>$reason]),5,2);$waNote=$wr[0]?' WhatsApp rejection message sent.':' WhatsApp सूचना: '.$wr[1];}catch(Throwable $waError){error_log('GS Suraha contribution reject WhatsApp error: '.$waError->getMessage());$waNote=' WhatsApp संदेश नहीं भेजा जा सका; rejection सुरक्षित है।';}}$msg='Contribution payment rejected.'.$waNote;}else{$msg='Rejection failed. कृपया Refresh करके Status जाँचें।';$msgType='danger';}
                }
            }
        }else{
            $mid=(int)($_POST['member_id']??0);$amount=(float)($_POST['amount']??0);$mode=(string)($_POST['mode']??'Cash');$status=(string)($_POST['status']??'Paid');$txn=trim((string)($_POST['txn_id']??''));
            if($mid<=0||$amount<=0){$msg='Select a member and enter a valid amount.';$msgType='danger';}
            elseif(!in_array($status,['Paid','Pending'],true)){$msg='Invalid contribution status.';$msgType='danger';}
            elseif($staffId>0 && !(int)$db->querySingle("SELECT COUNT(*) FROM staff_member_assignments WHERE member_id=$mid AND staff_id=$staffId")){$msg='आप केवल अपने assigned member का contribution दर्ज कर सकते हैं।';$msgType='danger';}
            else{
                $st=$db->prepare("INSERT INTO contributions(member_id,amount,month,mode,status,txn_id,created_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)");$st->bindValue(1,$mid,SQLITE3_INTEGER);$st->bindValue(2,$amount,SQLITE3_FLOAT);$st->bindValue(3,date('Y-m'),SQLITE3_TEXT);$st->bindValue(4,$mode,SQLITE3_TEXT);$st->bindValue(5,$status,SQLITE3_TEXT);$st->bindValue(6,$txn,SQLITE3_TEXT);
                if($st->execute()){$msg='Contribution recorded.';if($status==='Paid'&&getSetting('whatsapp_auto_contribution_enabled','0')==='1'){$mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=$mid")->fetchArray(SQLITE3_ASSOC);if($mm){try{$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'contribution',['amount'=>number_format($amount,2),'txn'=>$txn]),5,2);if(!$wr[0])$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1];}catch(Throwable $waError){error_log('GS Suraha manual contribution WhatsApp error: '.$waError->getMessage());$msg.=' WhatsApp संदेश नहीं भेजा जा सका; payment entry सुरक्षित है।';}}}}else{$msg='Contribution save नहीं हुआ। कृपया दोबारा जाँचें।';$msgType='danger';}
            }
        }
        // Post/Redirect/Get prevents a second Verify click or browser refresh from
        // re-running the action and keeps the dashboard render separate from POST.
        $_SESSION['contribution_flash'] = ['msg'=>$msg, 'type'=>$msgType];
        session_write_close();
        header('Location: ?route=contributions', true, 303);
        exit;
    }
    $members=$db->query("SELECT m.id,m.code,m.name FROM members m WHERE m.status='Active'".$staffFilter." ORDER BY m.name");
    $focusId=(int)($_GET['focus']??0);
    $pending=$db->query("SELECT c.*,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Pending'".$staffContributionFilter." ORDER BY CASE WHEN c.id=".$focusId." THEN 0 ELSE 1 END,c.id ASC LIMIT 200");
    $recent=$db->query("SELECT c.*,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id WHERE 1=1".$staffContributionFilter." ORDER BY CASE WHEN c.id=".$focusId." THEN 0 ELSE 1 END,c.id DESC LIMIT 50");
    $summary=$db->query("SELECT COUNT(*) total,COALESCE(SUM(CASE WHEN status='Pending' THEN 1 ELSE 0 END),0) pending_count,COALESCE(SUM(CASE WHEN status='Paid' THEN amount ELSE 0 END),0) paid_total,COALESCE(SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END),0) rejected_count FROM contributions c WHERE 1=1".$staffContributionFilter)->fetchArray(SQLITE3_ASSOC)?:['total'=>0,'pending_count'=>0,'paid_total'=>0,'rejected_count'=>0];
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">COLLECTION CENTER</div><h1>Contributions / जमा राशि</h1><p>Monthly fixed contribution: <b><?=money((float)getSetting('monthly_contribution','1000'))?></b> per member. Pending भुगतान नीचे Verify करें।</p></div></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="kpis" style="margin-bottom:16px"><div class="kpi orange"><span>Pending Verification</span><b><?=number_format((int)$summary['pending_count'])?></b></div><div class="kpi green"><span>Total Paid Contribution</span><b><?=money((float)$summary['paid_total'])?></b></div><div class="kpi red"><span>Rejected Payments</span><b><?=number_format((int)$summary['rejected_count'])?></b></div></div>
    <div class="grid-3"><div class="panel"><h2>Record Payment / जमा दर्ज करें</h2><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><label>Member</label><select name="member_id" required><option value="">Select Member</option><?php while($m=$members->fetchArray(SQLITE3_ASSOC)): ?><option value="<?=$m['id']?>"><?=h($m['code'].' — '.$m['name'])?></option><?php endwhile; ?></select><label>Amount</label><input type="number" step="0.01" min="0.01" name="amount" value="<?=h(getSetting('monthly_contribution','1000'))?>" required><label>Mode</label><select name="mode"><option>Cash</option><option>UPI</option><option>Bank</option><option>Online</option></select><label>Status</label><select name="status"><option value="Pending">Pending — Verify बाद में</option><option value="Paid">Paid — केवल भुगतान जाँचने के बाद</option></select><label>Transaction ID</label><input name="txn_id"><button class="btn primary full">Save Payment</button></form><small class="muted block" style="margin-top:8px">Online/UPI भुगतान को बैंक/merchant record देखकर ही Paid करें।</small></div>
    <div class="panel span2"><div class="panel-head"><div><h2>Pending Contribution Verification</h2><small class="muted">Admin सभी Pending payments देख सकता है; Staff केवल assigned members के payments देखेगा।</small></div><span class="badge warning"><?=number_format((int)$summary['pending_count'])?> Pending</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Member</th><th>Amount</th><th>Mode / UTR</th><th>Verify / Reject</th></tr></thead><tbody><?php $hasPending=false;while($r=$pending->fetchArray(SQLITE3_ASSOC)){$hasPending=true; ?><tr id="contribution-<?=$r['id']?>" class="<?=((int)($_GET['focus']??0)===(int)$r['id'])?'focus-row':''?>"><td><?=h(safeDateTimeDisplay($r['created_at']??'', 'd M Y'))?><small class="block"><?=h($r['month']??'')?></small></td><td><b><?=h($r['name'])?></b><small class="block"><?=h($r['code'])?></small></td><td><b><?=money((float)$r['amount'])?></b></td><td><?=h($r['mode']??'')?> <small class="block"><?=h($r['txn_id']??'No UTR entered')?></small></td><td><form method="post" style="display:grid;gap:6px;min-width:150px"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="id" value="<?=$r['id']?>"><input name="reject_reason" placeholder="Reject reason (Reject के लिए)" aria-label="Reject reason"><div class="inline-form"><button class="btn small primary" name="action" value="approve">✓ Verify</button><button class="btn small danger" name="action" value="reject" onclick="return confirm('क्या आप इस payment को Reject करना चाहते हैं? Reject reason भरना जरूरी है।')">✕ Reject</button></div></form></td></tr><?php }if(!$hasPending): ?><tr><td colspan="5">अभी कोई Pending Contribution नहीं है। Member के भुगतान submit करने पर यहाँ दिखाई देगा।</td></tr><?php endif; ?></tbody></table></div></div></div>
    <div class="ml-table-card" style="margin-top:16px">
      <div class="ml-footer" style="border-bottom:1px solid #eef2f7;border-top:0">
        <span><b>Recent Contributions</b> · Latest 50 · Paid / Pending / Rejected</span>
      </div>
      <div class="table-wrap">
        <table class="ml-table gs-data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Date</th>
              <th>Member ID</th>
              <th>Name</th>
              <th>Amount</th>
              <th>Mode</th>
              <th>Status</th>
              <th>Txn / Receipt</th>
            </tr>
          </thead>
          <tbody>
            <?php $hasRecent=false; $ri=1; while($r=$recent->fetchArray(SQLITE3_ASSOC)): $hasRecent=true;
              $st=strtolower((string)($r['status']??''));
            ?>
            <tr id="recent-contribution-<?=$r['id']?>">
              <td><?=$ri++?></td>
              <td><?=h(safeDateTimeDisplay($r['created_at']??'', 'd M Y'))?> <small class="muted"><?=h($r['month']??'')?></small></td>
              <td><span class="ml-code"><?=h($r['code'])?></span></td>
              <td><b><?=h($r['name'])?></b></td>
              <td><b><?=money((float)$r['amount'])?></b></td>
              <td><?=h($r['mode']??'')?></td>
              <td>
                <?php if($st==='paid'): ?><span class="ml-status active">✓ Paid</span>
                <?php elseif($st==='rejected'): ?><span class="ml-status closed">Rejected</span>
                <?php else: ?><span class="ml-status inactive"><?=h($r['status'])?></span><?php endif; ?>
                <?php if($st==='rejected' && trim((string)($r['reject_reason']??''))!==''): ?>
                  <small class="muted"> <?=h($r['reject_reason'])?></small>
                <?php endif; ?>
              </td>
              <td class="ml-actions">
                <span class="muted"><?=h($r['txn_id']??'')?></span>
                <?php if(($r['status']??'')==='Paid'): ?>
                  <a class="ml-act view" href="?route=payment-receipt&amp;type=contribution&amp;id=<?=$r['id']?>" target="_blank" rel="noopener">🧾 Slip</a>
                  <a class="ml-act edit" href="?route=send-payment-slip&amp;type=contribution&amp;id=<?=$r['id']?>" target="_blank" rel="noopener">📤 Send</a>
                <?php endif; ?>
              </td>
            </tr>
            <?php endwhile; if(!$hasRecent): ?>
            <tr><td colspan="8" class="ml-empty">अभी कोई contribution record नहीं है।</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Contributions',$c); exit;
}

if($route==='contribution-reminders'){
    requireRole(['admin','staff']);
    $msg=''; $msgType='success'; $monthlyRaw=trim(getSetting('monthly_contribution','1000')); $monthlyDefault=$monthlyRaw===''?1000.0:(float)$monthlyRaw; if(!is_finite($monthlyDefault)||$monthlyDefault<0)$monthlyDefault=1000.0; $monthlyExpr=number_format($monthlyDefault,2,'.','');
    $month=trim((string)($_GET['month']??date('Y-m')));
    if(!preg_match('/^\d{4}-\d{2}$/',$month)) $month=date('Y-m');
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $mid=(int)($_POST['member_id']??0); $channel=$_POST['channel']??''; $targetMonth=trim((string)($_POST['month']??$month));
        $row=$db->query("SELECT m.id AS member_id,m.name,m.code,m.mobile,{$monthlyExpr} AS monthly_due,COALESCE((SELECT SUM(c.amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid' AND c.month='".SQLite3::escapeString($targetMonth)."'),0) AS paid_this_month FROM members m WHERE m.id=$mid AND m.status='Active'")->fetchArray(SQLITE3_ASSOC);
        if(!$row){$msg='Member not found.';$msgType='danger';}
        elseif(!in_array($channel,['WhatsApp','SMS'],true)){$msg='Invalid reminder channel.';$msgType='danger';}
        else{
            $due=max(0,(float)$row['monthly_due']-(float)$row['paid_this_month']);
            if($due<=0){$msg='This member has already completed the contribution for this month.';$msgType='warning';}
            else{
                $row['monthly_due']=$due; $row['month']=$targetMonth; $paymentLink=paymentReminderLink('contribution',$due,$mid,0,$targetMonth,'CONTRIBUTION-'.$mid.'-'.$targetMonth); $message=contributionReminderText($row,$paymentLink); $sent=false;
                if($channel==='WhatsApp' && getSetting('whatsapp_provider_mode','Meta Cloud API')!=='Click to Chat'){
                    [$sent,$apiMsg]=sendWhatsAppMeta((string)$row['mobile'],$message,'Contribution',number_format($due,2),$targetMonth.'-01');
                    if(!$sent && getSetting('whatsapp_provider_mode','Meta Cloud API')==='Generic Provider API'){
                        $digits=preg_replace('/\D+/','',(string)$row['mobile']); if(strlen($digits)===10)$digits='91'.$digits;
                        $api=trim((string)getSetting('whatsapp_api_url')); $key=trim((string)getSetting('whatsapp_api_key'));
                        if($api!==''){
                            $payload=['to'=>$digits,'phone'=>$digits,'message'=>$message,'amount'=>number_format($due,2,'.',''),'type'=>'contribution_reminder','month'=>$targetMonth]; $headers=['Content-Type: application/json']; if($key!=='')$headers[]='Authorization: Bearer '.$key;
                            $ch=curl_init($api); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE),CURLOPT_TIMEOUT=>20]); $resp=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch); $sent=!$err&&$code>=200&&$code<300; $apiMsg=$sent?'WhatsApp provider sent successfully.':'WhatsApp provider failed'.($code?' (HTTP '.$code.')':'').($err?': '.$err:'');
                        }
                    }
                    $msg=$apiMsg; $msgType=$sent?'success':'danger';
                } elseif($channel==='SMS' && getSetting('sms_provider')==='Generic REST API'){
                    [$sent,$apiMsg]=sendGenericSmsApi((string)$row['mobile'],$message); $msg=$apiMsg; $msgType=$sent?'success':'danger';
                } else { $msg=$channel.' reminder तैयार है — Hindi message will open in the selected app.'; }
                $st=$db->prepare("INSERT INTO contribution_reminder_logs(member_id,channel,month) VALUES(?,?,?)"); $st->bindValue(1,$mid); $st->bindValue(2,$channel); $st->bindValue(3,$targetMonth); $st->execute();
            }
        }
        $month=$targetMonth;
    }
    $sql="SELECT m.id AS member_id,m.name,m.code,m.mobile,COALESCE($monthlyExpr,0) AS monthly_due,COALESCE((SELECT SUM(c.amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid' AND c.month='".SQLite3::escapeString($month)."'),0) AS paid_this_month,COALESCE((SELECT created_at FROM contribution_reminder_logs rl WHERE rl.member_id=m.id AND rl.month='".SQLite3::escapeString($month)."' ORDER BY rl.id DESC LIMIT 1),'') AS last_reminder FROM members m WHERE m.status='Active' ORDER BY m.name";
    if((string)($_GET['download']??'')==='csv'){
        $reportRows=$db->query($sql); $filename='contribution-reminders-'.$month.'.csv';
        header('Content-Type: text/csv; charset=UTF-8'); header('Content-Disposition: attachment; filename="'.$filename.'"'); header('Cache-Control: no-store, no-cache, must-revalidate');
        echo "\xEF\xBB\xBF"; $out=fopen('php://output','w');
        fputcsv($out,['Contribution Reminder Report','Month',$month]);
        fputcsv($out,['Member ID','Member Name','Mobile','Monthly Due','Paid This Month','Pending Balance','Last Reminder']);
        $reportCount=0; $reportDue=0.0; $reportPaid=0.0; $reportBalance=0.0;
        while($r=$reportRows->fetchArray(SQLITE3_ASSOC)){
            $balance=max(0,(float)$r['monthly_due']-(float)$r['paid_this_month']); if($balance<=0) continue;
            $reportCount++; $reportDue+=(float)$r['monthly_due']; $reportPaid+=(float)$r['paid_this_month']; $reportBalance+=$balance;
            fputcsv($out,[$r['code'],$r['name'],$r['mobile'],number_format((float)$r['monthly_due'],2,'.',''),number_format((float)$r['paid_this_month'],2,'.',''),number_format($balance,2,'.',''),$r['last_reminder']]);
        }
        fputcsv($out,[]); fputcsv($out,['Summary','Pending Members',$reportCount,'Monthly Due',number_format($reportDue,2,'.',''),'Paid',number_format($reportPaid,2,'.',''),'Balance',number_format($reportBalance,2,'.','')]); fclose($out); exit;
    }
    $rows=$db->query($sql); ob_start(); ?>
    <div class="ml-page">
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">🔔</div>
          <div>
            <h1>Contribution Reminders</h1>
            <p>मासिक योगदान के pending members · WhatsApp / SMS</p>
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <a class="ml-btn-add" href="?route=contribution-reminders&amp;month=<?=h($month)?>&amp;download=csv">⬇ Report</a>
          <a class="ml-btn-add" style="background:rgba(255,255,255,.2);color:#fff" href="?route=communications">💬 Settings</a>
        </div>
      </div>
      <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>

      <form class="ml-filters cr-filters" method="get" action="">
        <input type="hidden" name="route" value="contribution-reminders">
        <div class="cr-filter-row">
          <input type="month" name="month" value="<?=h($month)?>" class="cr-month">
          <button type="submit" class="ml-btn-search">View</button>
          <span class="cr-hint"><?=h(date('M Y',strtotime($month.'-01')))?> · pending only</span>
        </div>
      </form>

      <div class="ml-table-card">
        <div class="table-wrap">
          <table class="ml-table gs-data-table gs-reminder-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Member ID</th>
                <th>Name</th>
                <th>Due</th>
                <th>Month</th>
                <th>Paid</th>
                <th>Balance</th>
                <th>Mobile</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
            <?php $count=0; while($r=$rows->fetchArray(SQLITE3_ASSOC)):
              $balance=max(0,(float)$r['monthly_due']-(float)$r['paid_this_month']);
              if($balance<=0) continue;
              $count++;
              $digits=preg_replace('/\D+/','',(string)$r['mobile']);
              if(strlen($digits)===10)$digits='91'.$digits;
              elseif(str_starts_with($digits,'0'))$digits='91'.substr($digits,1);
              $rr=$r; $rr['monthly_due']=$balance; $rr['month']=$month; $rr['code']=$r['code'];
              $paymentLink=paymentReminderLink('contribution',$balance,(int)$r['member_id'],0,$month,'CONTRIBUTION-'.(int)$r['member_id'].'-'.$month);
              $msgText=contributionReminderText($rr,$paymentLink);
              $wa='https://wa.me/'.$digits.'?text='.rawurlencode($msgText);
              $sms='sms:'.$digits.'?body='.rawurlencode($msgText);
            ?>
              <tr>
                <td><?=$count?></td>
                <td><span class="ml-code"><?=h($r['code'])?></span></td>
                <td><b><?=h($r['name'])?></b></td>
                <td><?=money((float)$r['monthly_due'])?></td>
                <td><?=h(date('M Y',strtotime($month.'-01')))?></td>
                <td><?=money((float)$r['paid_this_month'])?></td>
                <td><b class="mb-available"><?=money($balance)?></b></td>
                <td><?=h($r['mobile'])?></td>
                <td class="ml-actions">
                  <a class="ml-act view" target="_blank" rel="noopener" href="<?=h($wa)?>">💬 WA</a>
                  <a class="ml-act edit" href="<?=h($sms)?>">📱 SMS</a>
                  <form method="post" style="display:inline;margin:0">
                    <input type="hidden" name="csrf" value="<?=h(csrf())?>">
                    <input type="hidden" name="member_id" value="<?=$r['member_id']?>">
                    <input type="hidden" name="month" value="<?=h($month)?>">
                    <input type="hidden" name="channel" value="WhatsApp">
                    <button class="ml-act view" type="submit" title="API WhatsApp" style="border:0;cursor:pointer">API WA</button>
                  </form>
                  <form method="post" style="display:inline;margin:0">
                    <input type="hidden" name="csrf" value="<?=h(csrf())?>">
                    <input type="hidden" name="member_id" value="<?=$r['member_id']?>">
                    <input type="hidden" name="month" value="<?=h($month)?>">
                    <input type="hidden" name="channel" value="SMS">
                    <button class="ml-act edit" type="submit" title="API SMS" style="border:0;cursor:pointer">API SMS</button>
                  </form>
                </td>
              </tr>
            <?php endwhile; if(!$count): ?>
              <tr><td colspan="9" class="ml-empty">No pending contribution reminders for this month.</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
        <div class="ml-footer">
          <span>Pending members: <?=number_format($count)?></span>
          <small class="muted">WhatsApp/SMS buttons open apps · API buttons use configured providers</small>
        </div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Contribution Reminders',$c); exit;
}

if($route==='emi-reminders'){
    requireRole(['admin','staff']);
    $repairedSchedules=repairMissingEmiSchedules();
    $msg=''; $msgType='success';
    if($repairedSchedules>0){ $msg='EMI schedule automatically restored for existing active loan(s).'; }
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $emiId=(int)($_POST['emi_id']??0); $channel=$_POST['channel']??'';
        $row=$db->query("SELECT e.id AS emi_id,e.installment_no,e.due_date,e.amount,e.paid_amount,m.id AS member_id,m.name,m.mobile,l.id AS loan_id FROM emi_schedule e JOIN loans l ON l.id=e.loan_id JOIN members m ON m.id=l.member_id WHERE e.id=$emiId AND e.status!='Paid'")->fetchArray(SQLITE3_ASSOC);
        if(!$row){ $msg='EMI not found or already paid.'; $msgType='danger'; }
        elseif(!in_array($channel,['WhatsApp','SMS','WhatsApp API','SMS API'],true)){ $msg='Invalid reminder channel.'; $msgType='danger'; }
        else { $out=max(0,(float)$row['amount']-(float)$row['paid_amount']); $paymentLink=paymentReminderLink('emi',$out,(int)$row['member_id'],(int)$row['emi_id'],'','EMI-'.(int)$row['emi_id'].'-'.date('YmdHis')); $message=hindiReminderText($row,$out,$paymentLink); $sent=false;
            if($channel==='WhatsApp API'){ [$sent,$apiMsg]=sendWhatsAppMeta((string)$row['mobile'],$message,'EMI #'.$row['installment_no'],number_format($out,2),$row['due_date']); $msg=$apiMsg; $msgType=$sent?'success':'danger'; }
            elseif($channel==='SMS API'){ [$sent,$apiMsg]=sendGenericSmsApi((string)$row['mobile'],$message); $msg=$apiMsg; $msgType=$sent?'success':'danger'; }
            else { $msg=$channel.' reminder तैयार है — Hindi message will open in the selected app.'; }
            $st=$db->prepare("INSERT INTO reminder_logs(member_id,emi_id,channel) VALUES(?,?,?)");$st->bindValue(1,(int)$row['member_id']);$st->bindValue(2,$emiId);$st->bindValue(3,$channel);$st->execute(); }
    }
    $days=isset($_GET['days']) ? max(0,min(36500,(int)$_GET['days'])) : 36500;
    $dateFilter='';
    if(isset($_GET['days'])){
        if((int)$_GET['days']===0) $dateFilter=" AND COALESCE(e.due_date,date('now'))<=date('now')";
        else $dateFilter=" AND COALESCE(e.due_date,date('now'))<=date('now','+".(int)$_GET['days']." day')";
    }
    $sql="SELECT e.id AS emi_id,e.installment_no,e.due_date,e.amount,e.paid_amount,e.status,m.id AS member_id,m.name,m.code,m.mobile,l.id AS loan_id,
        COALESCE((SELECT rl.created_at FROM reminder_logs rl WHERE rl.emi_id=e.id ORDER BY rl.id DESC LIMIT 1),'') last_reminder
        FROM emi_schedule e JOIN loans l ON l.id=e.loan_id JOIN members m ON m.id=l.member_id
        WHERE MAX(COALESCE(e.amount,0)-COALESCE(e.paid_amount,0),0)>0 {$dateFilter}
        ORDER BY CASE WHEN e.due_date IS NULL OR e.due_date='' THEN 1 ELSE 0 END,e.due_date ASC,m.name ASC";
    $rows=$db->query($sql);
    ob_start(); ?>
    <div class="page-title reminder-page-title"><div><div class="eyebrow">COMMUNICATION CENTER</div><h1>EMI Reminders</h1><p>Send a ready-to-use reminder to members by WhatsApp or SMS. <span class="hi-sub">सदस्यों को ईएमआई रिमाइंडर भेजें।</span></p></div><a class="btn" href="?route=communications">💬 Communication Settings</a></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="panel"><div class="panel-head"><div><h2>Pending / Due EMI</h2><small class="muted">सभी Pending EMI दिखेंगी · Payment API URL configured होने पर automatic payment link reminder में जुड़ता है; वरना UPI link.</small></div><div class="inline-form"><a class="btn small" href="?route=emi-reminders&days=0">Overdue</a><a class="btn small" href="?route=emi-reminders&days=7">7 Days</a><a class="btn small" href="?route=emi-reminders&days=30">30 Days</a><a class="btn small" href="?route=emi-reminders">All Pending</a></div></div>
    <div class="table-wrap emi-reminder-table-wrap"><table class="emi-reminder-table"><thead><tr><th>Member</th><th>EMI</th><th>Due Date</th><th>Outstanding</th><th>Mobile</th><th>Reminder</th></tr></thead><tbody>
    <?php $count=0; while($r=$rows->fetchArray(SQLITE3_ASSOC)): $count++; $out=max(0,(float)$r['amount']-(float)$r['paid_amount']); $digits=preg_replace('/\D+/','',(string)$r['mobile']); if(strlen($digits)===10)$digits='91'.$digits; elseif(str_starts_with($digits,'0'))$digits='91'.substr($digits,1); $overdue=$r['due_date']<date('Y-m-d'); $paymentLink=paymentReminderLink('emi',$out,(int)$r['member_id'],(int)$r['emi_id'],'','EMI-'.(int)$r['emi_id'].'-'.date('YmdHis')); $msgText=hindiReminderText($r,$out,$paymentLink); $wa='https://wa.me/'.$digits.'?text='.rawurlencode($msgText); $sms='sms:'.$digits.'?body='.rawurlencode($msgText); ?>
      <tr><td><b><?=h($r['name'])?></b><small class="block"><?=h($r['code'])?> · Loan #<?=h((string)$r['loan_id'])?></small></td><td>EMI #<?=h((string)$r['installment_no'])?></td><td><span class="badge <?=$overdue?'danger':'warning'?>"><?=h(date('d M Y',strtotime($r['due_date'])))?><?=$overdue?' · Overdue':''?></span></td><td><b><?=money($out)?></b></td><td><?=h($r['mobile'])?></td><td><div class="inline-form"><a class="btn small" target="_blank" rel="noopener" href="<?=h($wa)?>" onclick="return markReminder(<?=h((string)$r['emi_id'])?>,'WhatsApp',this)">💬 WhatsApp</a><a class="btn small" href="<?=h($sms)?>" onclick="return markReminder(<?=h((string)$r['emi_id'])?>,'SMS',this)">📱 SMS</a><button class="btn small" type="button" onclick="sendReminderApi(<?=h((string)$r['emi_id'])?>,'WhatsApp API',this)">⚙️ API WA</button><button class="btn small" type="button" onclick="sendReminderApi(<?=h((string)$r['emi_id'])?>,'SMS API',this)">⚙️ API SMS</button></div><?php if($r['last_reminder']): ?><small class="block muted">Last: <?=h($r['last_reminder'])?></small><?php endif; ?></td></tr>
    <?php endwhile; if(!$count): ?><tr><td colspan="6"><div class="alert success">No unpaid EMI found. पहले Loan/EMI schedule बनना जरूरी है।</div></td></tr><?php endif; ?></tbody></table></div></div>
    <div class="panel"><h2>How it works</h2><div class="rules"><div><span>WhatsApp</span><b>Opens WhatsApp with the message ready</b></div><div><span>SMS</span><b>Opens the phone's SMS app with the message ready</b></div><div><span>API</span><b>API WA और API SMS buttons configured credentials के साथ direct server-side भेजेंगे.</b></div><div><span>Automatic sending</span><b>Requires configured WhatsApp/SMS provider API credentials.</b></div></div></div>
    <script>function markReminder(id,channel,el){try{fetch(location.href,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'<?=h(csrf())?>',emi_id:String(id),channel:channel}).toString(),keepalive:true}).catch(function(){});el.setAttribute('data-reminder','prepared');}catch(e){}return true;} function sendReminderApi(id,channel,el){var old=el.innerText;el.disabled=true;el.innerText='Sending...';fetch(location.href,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'<?=h(csrf())?>',emi_id:String(id),channel:channel}).toString()}).then(function(r){return r.text();}).then(function(t){document.open();document.write(t);document.close();}).catch(function(){el.disabled=false;el.innerText=old;alert('API request failed. Please check API URL, token and PHP cURL.');});return false;}</script>
    <?php $c=ob_get_clean(); layout('EMI Reminders',$c); exit;
}

if($route==='notifications'){
    requireLogin(); $u=user(); $items=[]; $msg=''; $msgType='success';

    // Admin and Staff can send an in-app notification to one member or all members.
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $action=(string)($_POST['action']??'');
        if($action==='delete_activity_notice' && in_array($u['role'],['admin','staff'],true)){
            $key=trim((string)($_POST['notice_key']??''));
            if($key!==''){
                $st=$db->prepare("INSERT OR IGNORE INTO activity_notice_dismissals(user_id,notice_key) VALUES(?,?)");
                $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER);
                $st->bindValue(2,$key,SQLITE3_TEXT);
                $st->execute();
                audit('activity_notice_deleted',$key);
            }
            header('Location: ?route=notifications'); exit;
        }
        if($action==='send_member_notification' && in_array($u['role'],['admin','staff'],true)){
            $title=trim((string)($_POST['title']??''));
            $message=trim((string)($_POST['message']??''));
            $target=(string)($_POST['member_id']??'all');
            if($title==='' || $message===''){$msg='Title और message दोनों भरें।';$msgType='danger';}
            else{
                $memberId=($target==='all'||$target==='')?null:(int)$target;
                if($memberId!==null && !(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE id=".$memberId." AND status='Active'")){
                    $msg='Selected member नहीं मिला।'; $msgType='danger';
                } else {
                    $st=$db->prepare("INSERT INTO member_notifications(member_id,title,message,created_by) VALUES(?,?,?,?)");
                    if($memberId===null) $st->bindValue(1,null,SQLITE3_NULL); else $st->bindValue(1,$memberId,SQLITE3_INTEGER);
                    $st->bindValue(2,$title,SQLITE3_TEXT); $st->bindValue(3,$message,SQLITE3_TEXT); $st->bindValue(4,(int)$u['id'],SQLITE3_INTEGER);
                    $st->execute(); $msg=$memberId===null?'Notification सभी members को भेज दिया गया।':'Notification member को भेज दिया गया।';
                }
            }
        } elseif($action==='hide_notification' && $u['role']==='member'){
            $nid=(int)($_POST['notification_id']??0);
            $st=$db->prepare("INSERT OR IGNORE INTO notification_dismissals(user_id,notification_id) VALUES(?,?)");
            $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$nid,SQLITE3_INTEGER); $st->execute();
            header('Location: ?route=notifications'); exit;
        } elseif($action==='delete_member_activity' && $u['role']==='member'){
            $key=trim((string)($_POST['notice_key']??''));
            if(preg_match('/(?:route=loan-applications(?:&focus=|\|)|loan\|)(\d+)/',$key,$mm)) $key='loan|'.(int)$mm[1];
            if($key!==''){
                $st=$db->prepare("INSERT OR IGNORE INTO activity_notice_dismissals(user_id,notice_key) VALUES(?,?)");
                $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$key,SQLITE3_TEXT); $st->execute();
            }
            header('Location: ?route=notifications'); exit;
        }
    }

    if($u['role']==='staff'){
        $r=$db->query("SELECT la.id AS id, 'New loan application' title, 'A member submitted a loan application assigned to you. Staff review and remarks are required before forwarding.' detail, la.created_at FROM loan_applications la WHERE la.status='Pending' AND la.assigned_staff_id=".(int)$u['id']." ORDER BY la.id DESC LIMIT 20");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=loan-applications';$x['custom']=false;$items[]=$x;}
    } elseif($u['role']==='admin'){
        $r=$db->query("SELECT mc.id AS id, 'Member closure request' AS title, 'Member: '||COALESCE(m.name,'Unknown member')||' (ID '||COALESCE(m.code,'—')||'). Account closure and refund request needs review.' AS detail, mc.created_at, '?route=member-close&id='||mc.member_id AS href FROM member_closures mc JOIN members m ON m.id=mc.member_id WHERE mc.status='Pending' ORDER BY mc.id DESC LIMIT 50");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['custom']=false;$x['notice_key']='closure|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT la.id AS id, CASE WHEN la.status='Approved' THEN 'Loan application active / approved' WHEN la.status='Rejected' THEN 'Loan application rejected' WHEN la.status='Forwarded' THEN 'Loan application forwarded by Staff' ELSE 'Loan application verification pending' END title, 'Member: '||COALESCE(m.name,'Unknown member')||' (ID '||COALESCE(m.code,'—')||'). '||CASE WHEN la.status='Approved' THEN 'Loan is active / approved.' WHEN la.status='Rejected' THEN COALESCE(NULLIF(la.review_note,''),'Loan application rejected.') WHEN la.status='Forwarded' THEN COALESCE(NULLIF(la.staff_remark,''),'Staff has forwarded the application for Admin review.') ELSE 'Application received and waiting for review.' END detail, la.created_at, '?route=loan-applications&focus='||la.id href FROM loan_applications la JOIN members m ON m.id=la.member_id ORDER BY la.id DESC LIMIT 30");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['custom']=false;$x['notice_key']='loan|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT c.id AS id, CASE WHEN c.status='Paid' THEN 'Contribution payment verified' WHEN c.status='Rejected' THEN 'Contribution payment rejected' ELSE 'Contribution verification pending' END title, 'Member: '||COALESCE(m.name,'Unknown member')||' (ID '||COALESCE(m.code,'—')||'). '||CASE WHEN c.status='Paid' THEN 'Contribution payment verified.' WHEN c.status='Rejected' THEN COALESCE(NULLIF(c.reject_reason,''),'Contribution payment rejected.') ELSE 'A contribution payment is waiting for verification.' END detail, c.created_at, '?route=contributions&focus='||c.id href FROM contributions c JOIN members m ON m.id=c.member_id ORDER BY c.id DESC LIMIT 30");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['custom']=false;$x['notice_key']='contribution|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT p.id AS id, CASE WHEN p.status='Paid' OR p.status='Approved' THEN 'EMI payment verified' WHEN p.status='Rejected' THEN 'EMI payment rejected' ELSE 'EMI payment verification pending' END title, 'Member: '||COALESCE(m.name,'Unknown member')||' (ID '||COALESCE(m.code,'—')||'). '||CASE WHEN p.status='Paid' OR p.status='Approved' THEN 'EMI payment verified.' WHEN p.status='Rejected' THEN COALESCE(NULLIF(p.reject_reason,''),'EMI payment rejected.') ELSE 'An EMI payment is waiting for verification.' END detail, p.created_at, '?route=emi-payments&focus='||p.id href FROM payments p JOIN members m ON m.id=p.member_id ORDER BY p.id DESC LIMIT 30");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['custom']=false;$x['notice_key']='payment|'.$x['id'];$items[]=$x;}
    } else {
        $mid=(int)$u['member_id']; $uid=(int)$u['id'];
        $r=$db->query("SELECT la.id AS id, CASE WHEN la.status='Pending' THEN 'Loan application submitted' WHEN la.status='Forwarded' THEN 'Loan application forwarded to Admin' WHEN la.status='Approved' THEN 'Loan application approved' ELSE 'Loan application update' END title, CASE WHEN la.status='Pending' THEN 'Your application is with Staff for initial review.' WHEN la.status='Forwarded' THEN COALESCE(NULLIF(la.staff_remark,''),'Staff has forwarded your application to Admin.') WHEN la.status='Approved' THEN 'Your loan application has been approved.' ELSE COALESCE(NULLIF(la.review_note,''),'Your loan application status was updated.') END detail, la.created_at FROM loan_applications la WHERE la.member_id=$mid ORDER BY la.id DESC LIMIT 20");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=member-loan-apply';$x['custom']=false;$x['notice_key']='loan|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT e.id AS id, 'EMI due' title, 'An EMI is due. Please make your payment.' detail, e.due_date AS created_at FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE l.member_id=$mid AND e.status!='Paid' AND e.due_date<=date('now') ORDER BY e.due_date DESC LIMIT 20");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=member-emi-pay';$x['custom']=false;$x['notice_key']='emi|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT c.id AS id, CASE WHEN c.status='Paid' THEN 'Contribution payment verified' WHEN c.status='Rejected' THEN 'Contribution payment rejected' ELSE 'Contribution payment submitted' END title, CASE WHEN c.status='Paid' THEN 'Your contribution payment has been verified.' WHEN c.status='Rejected' THEN COALESCE(NULLIF(c.reject_reason,''),'Your contribution payment was rejected.') ELSE 'Your contribution payment is waiting for admin verification.' END detail, c.created_at FROM contributions c WHERE c.member_id=$mid ORDER BY c.id DESC LIMIT 20");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=member-profile';$x['custom']=true;$x['notice_key']='contribution|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT p.id AS id, CASE WHEN p.status='Paid' THEN 'EMI payment verified' WHEN p.status='Rejected' THEN 'EMI payment rejected' ELSE 'Payment submitted' END title, CASE WHEN p.status='Paid' THEN 'Your EMI payment has been verified.' WHEN p.status='Rejected' THEN COALESCE(NULLIF(p.reject_reason,''),'Your EMI payment was rejected.') ELSE 'Your online payment is waiting for verification.' END detail, p.created_at FROM payments p WHERE p.member_id=$mid ORDER BY p.id DESC LIMIT 20");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=member-emi-pay';$x['custom']=false;$x['notice_key']='payment|'.$x['id'];$items[]=$x;}
        $r=$db->query("SELECT n.id,n.title,n.message AS detail,n.created_at FROM member_notifications n WHERE (n.member_id=$mid OR n.member_id IS NULL) AND NOT EXISTS (SELECT 1 FROM notification_dismissals d WHERE d.notification_id=n.id AND d.user_id=$uid) ORDER BY n.id DESC LIMIT 50");
        while($x=$r->fetchArray(SQLITE3_ASSOC)){$x['href']='?route=notifications';$x['custom']=true;$items[]=$x;}
    }
    if($u['role']==='member'){
        $visible=[];
        foreach($items as $it){
            if(!empty($it['custom']) && empty($it['notice_key'])){ $visible[]=$it; continue; }
            $key=(string)($it['notice_key']??'');
            if($key===''){ $visible[]=$it; continue; }
            $st=$db->prepare("SELECT 1 FROM activity_notice_dismissals WHERE user_id=? AND notice_key=? LIMIT 1");
            $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER); $st->bindValue(2,$key,SQLITE3_TEXT);
            if(!$st->execute()->fetchArray(SQLITE3_NUM)) $visible[]=$it;
        }
        $items=$visible;
    }

    if(in_array($u['role'],['admin','staff'],true)){
        $visible=[];
        foreach($items as $it){
            if(!empty($it['custom'])){ $visible[]=$it; continue; }
            $key=(string)($it['notice_key']??($it['href'].'|'.($it['id']??0).'|'.($it['title']??'')));
            $st=$db->prepare("SELECT 1 FROM activity_notice_dismissals WHERE user_id=? AND notice_key=? LIMIT 1");
            $st->bindValue(1,(int)$u['id'],SQLITE3_INTEGER);
            $st->bindValue(2,$key,SQLITE3_TEXT);
            if(!$st->execute()->fetchArray(SQLITE3_NUM)){ $it['notice_key']=$key; $visible[]=$it; }
        }
        $items=$visible;
    }
    usort($items,fn($a,$b)=>strcmp((string)$b['created_at'],(string)$a['created_at']));
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">ALERT CENTER</div><h1>Notifications</h1><p>Loan applications, review actions and payment reminders. <span class="hi-sub">ऋण आवेदन, समीक्षा और भुगतान की सूचनाएँ।</span></p></div></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <?php if(in_array($u['role'],['admin','staff'],true)): ?>
    <div class="panel"><div class="panel-head"><h2>📣 Send Member Notification <span class="hi-inline">सदस्य को ऐप पर सूचना भेजें</span></h2><small class="muted">Admin और Staff दोनों notification भेज सकते हैं।</small><span class="badge info"><?=h(ucfirst($u['role']))?> can send</span></div>
      <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="send_member_notification">
        <div><label>Send To</label><select name="member_id"><option value="all">All Active Members / सभी सदस्य</option><?php $mr=$db->query("SELECT id,code,name FROM members WHERE status='Active' ORDER BY name"); while($m=$mr->fetchArray(SQLITE3_ASSOC)): ?><option value="<?=$m['id']?>"><?=h($m['name'].' ('.$m['code'].')')?></option><?php endwhile; ?></select></div>
        <div><label>Title / शीर्षक</label><input name="title" maxlength="120" required placeholder="Important notice"></div>
        <div class="span2"><label>Message / संदेश</label><textarea name="message" rows="3" maxlength="1000" required placeholder="Message members will see in the app"></textarea></div>
        <div class="span2"><button class="btn primary">📤 Send in App / ऐप पर भेजें</button></div>
      </form>
    </div>
    <?php endif; ?>
    <div class="panel"><div class="panel-head"><h2>Notifications Summary <span class="hi-inline">सूचना सारांश</span></h2><span class="badge <?=count($items)?'warning':'success'?>"><?=count($items)?> active</span></div>
    <?php if(!$items): ?><div class="alert success">No notifications right now.</div><?php else: ?><div class="notification-list">
    <?php foreach(array_slice($items,0,50) as $it): ?>
      <?php if(!empty($it['custom']) && $u['role']==='member'): ?>
        <div class="notification-item"><span class="notification-dot">📣</span><span class="notification-copy"><b><?=h($it['title'])?></b><small><?=h($it['detail'])?></small><em><?=h($it['created_at'])?></em></span><?php if(!empty($it['notice_key'])): ?><form method="post" class="activity-delete-form" onsubmit="return confirm('इस contribution notice को delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_member_activity"><input type="hidden" name="notice_key" value="<?=h($it['notice_key'])?>"><button class="btn small danger" type="submit">🗑️ Delete</button></form><?php else: ?><form method="post" class="activity-delete-form"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="hide_notification"><input type="hidden" name="notification_id" value="<?=h((string)$it['id'])?>"><button class="btn small" type="submit">Hide / छुपाएँ</button></form><?php endif; ?></div>
      <?php else: ?><div class="notification-item"><a class="notification-main" href="<?=h($it['href'])?>"><span class="notification-dot">🔔</span><span><b><?=h($it['title'])?></b><small><?=h($it['detail'])?></small><em><?=h($it['created_at'])?></em></span><strong>→</strong></a><?php if(in_array($u['role'],['admin','staff'],true) && !empty($it['notice_key'])): ?><form method="post" class="activity-delete-form" onsubmit="return confirm('इस activity notice को delete करें? Original record delete नहीं होगा।')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_activity_notice"><input type="hidden" name="notice_key" value="<?=h($it['notice_key'])?>"><button class="btn small danger" type="submit">🗑️ Delete</button></form><?php endif; ?></div><?php endif; ?>
    <?php endforeach; ?></div><?php endif; ?></div>
    <?php $c=ob_get_clean(); layout('Notifications',$c); exit;
}

if($route==='loan-applications'){
    requireRole(['admin','staff']);
    $msg=''; $msgType='success'; $currentRole=user()['role'];
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $id=(int)($_POST['id']??0);$action=$_POST['action']??'';$note=trim($_POST['note']??'');
        $app=$db->query("SELECT * FROM loan_applications WHERE id=$id")->fetchArray(SQLITE3_ASSOC);
        if(!$app){$msg='Loan application not found.';$msgType='danger';}
        elseif($currentRole==='staff' && (int)($app['assigned_staff_id']??0)!==(int)user()['id']){$msg='Access denied: this loan application is not assigned to you.';$msgType='danger';}
        elseif($currentRole==='admin' && $action==='assign_staff'){
            $newStaff=(int)($_POST['assigned_staff_id']??0); $reason=trim((string)($_POST['assignment_reason']??''));
            $validStaff=false;
            if($newStaff===0){$validStaff=true;} else { $chk=$db->prepare("SELECT id FROM users WHERE id=? AND role='staff'");$chk->bindValue(1,$newStaff,SQLITE3_INTEGER);$validStaff=(bool)$chk->execute()->fetchArray(SQLITE3_ASSOC); }
            if(!$validStaff){$msg='कृपया सही Staff चुनें।';$msgType='danger';}
            else {
                $oldStaff=(int)($app['assigned_staff_id']??0); $oldStaff=$oldStaff>0?$oldStaff:null; $newValue=$newStaff>0?$newStaff:null;
                $st=$db->prepare("UPDATE loan_applications SET assigned_staff_id=? WHERE id=?");$st->bindValue(1,$newValue, $newValue===null?SQLITE3_NULL:SQLITE3_INTEGER);$st->bindValue(2,$id,SQLITE3_INTEGER);
                if($st->execute()){
                    $hist=$db->prepare("INSERT INTO loan_application_assignment_history(loan_application_id,old_staff_id,new_staff_id,changed_by,reason) VALUES(?,?,?,?,?)");
                    $hist->bindValue(1,$id,SQLITE3_INTEGER);$hist->bindValue(2,$oldStaff,$oldStaff===null?SQLITE3_NULL:SQLITE3_INTEGER);$hist->bindValue(3,$newValue,$newValue===null?SQLITE3_NULL:SQLITE3_INTEGER);$hist->bindValue(4,(int)user()['id'],SQLITE3_INTEGER);$hist->bindValue(5,$reason,SQLITE3_TEXT);$hist->execute();
                    $msg='Loan application का Staff assignment अपडेट हो गया।';
                } else {$msg='Staff assignment अपडेट नहीं हो पाया।';$msgType='danger';}
            }
        }
        elseif($currentRole==='staff' && $action==='forward'){
            if($app['status']!=='Pending'){$msg='This application is already processed or forwarded.';$msgType='warning';}
            elseif($note===''){$msg='Please enter Staff remarks before forwarding to Admin.';$msgType='danger';}
            else{
                $st=$db->prepare("UPDATE loan_applications SET status='Forwarded',staff_remark=?,staff_reviewed_by=?,staff_reviewed_at=datetime('now'),forwarded_at=datetime('now') WHERE id=? AND status='Pending'");
                $st->bindValue(1,$note);$st->bindValue(2,user()['id']);$st->bindValue(3,$id);
                if($st->execute() && $db->changes()===1){$msg='Application reviewed and forwarded to Admin.';}else{$msg='Application could not be forwarded.';$msgType='danger';}
            }
        } elseif($currentRole==='admin' && in_array($action,['approve','reject'],true)){
            if($app['status']!=='Forwarded'){$msg='Admin can act only after Staff forwards the application.';$msgType='warning';}
            elseif($action==='reject') {
                $st=$db->prepare("UPDATE loan_applications SET status='Rejected',reviewed_by=?,review_note=?,reviewed_at=datetime('now') WHERE id=? AND status='Forwarded'");$st->bindValue(1,user()['id']);$st->bindValue(2,$note);$st->bindValue(3,$id);
                if($st->execute()){$msg='Application rejected.'; if(getSetting('whatsapp_auto_loan_rejected_enabled','0')==='1'){ $mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$app['member_id'])->fetchArray(SQLITE3_ASSOC); if($mm){$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'loan_rejected',['amount'=>number_format((float)$app['requested'],2),'reason'=>$note])); if(!$wr[0])$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1];}} }else{$msg='Application could not be rejected.';$msgType='danger';}
            } else {
                $amount=(float)($_POST['approved_amount']??$app['requested']);$rate=(float)($_POST['interest_rate']??12);$tenure=(int)$app['tenure'];
                if($amount<=0||$rate<0||$tenure<1||$tenure>120){$msg='Invalid approval details.';$msgType='danger';}
                else{
                    $db->exec('BEGIN IMMEDIATE');
                    try{
                        $memberCheck=$db->prepare("SELECT status FROM members WHERE id=?");$memberCheck->bindValue(1,(int)$app['member_id'],SQLITE3_INTEGER);$memberStatus=(string)($memberCheck->execute()->fetchArray(SQLITE3_ASSOC)['status']??'');if($memberStatus!=='Active')throw new Exception('Member is not active');
                        $st=$db->prepare("UPDATE loan_applications SET status='Approved',approved_amount=?,interest_rate=?,reviewed_by=?,review_note=?,reviewed_at=datetime('now') WHERE id=? AND status='Forwarded'");
                        $st->bindValue(1,$amount);$st->bindValue(2,$rate);$st->bindValue(3,user()['id']);$st->bindValue(4,$note);$st->bindValue(5,$id);
                        if(!$st->execute() || $db->changes()!==1) throw new Exception('Application update failed');
                        $st=$db->prepare("INSERT INTO loans(member_id,principal,interest_rate,tenure,purpose) VALUES(?,?,?,?,?)");$st->bindValue(1,$app['member_id']);$st->bindValue(2,$amount);$st->bindValue(3,$rate);$st->bindValue(4,$tenure);$st->bindValue(5,$app['purpose']);
                        if(!$st->execute()) throw new Exception('Loan creation failed');
                        $loanId=(int)$db->lastInsertRowID();$schedule=loanAmortizationRows($amount,$rate,$tenure);
                        foreach($schedule as $idx=>$part){$i=$idx+1;$st=$db->prepare("INSERT INTO emi_schedule(loan_id,installment_no,due_date,amount,principal_component,interest_component) VALUES(?,?,?,?,?,?)");$st->bindValue(1,$loanId);$st->bindValue(2,$i);$st->bindValue(3,monthlyInstallmentDueDate($i));$st->bindValue(4,$part['amount']);$st->bindValue(5,$part['principal_component']);$st->bindValue(6,$part['interest_component']);if(!$st->execute())throw new Exception('EMI schedule creation failed');}
                        $db->exec('COMMIT');$msg='Loan approved and EMI schedule created.'; if(getSetting('whatsapp_auto_loan_approved_enabled','0')==='1'){ $mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$app['member_id'])->fetchArray(SQLITE3_ASSOC); if($mm){$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'loan_approved',['amount'=>number_format($amount,2),'loan_id'=>$loanId])); if(!$wr[0])$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1];}}
                    }catch(Throwable $e){$db->exec('ROLLBACK');$msg='Loan approval failed. No partial loan was created.';$msgType='danger';}
                }
            }
        } else {$msg='Invalid action for your role.';$msgType='danger';}
    }
    $staffId=(int)user()['id'];
    $where = $currentRole==='admin' ? '1=1' : 'a.assigned_staff_id='.$staffId;
    $apps=$db->query("SELECT a.*,m.name,m.code,m.bank_name,m.account_holder,m.account_number,m.ifsc,m.bank_upi_id,COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) deposit,COALESCE(NULLIF(au.display_name,''),au.username,'Not assigned') assigned_staff_name FROM loan_applications a JOIN members m ON m.id=a.member_id LEFT JOIN users au ON au.id=a.assigned_staff_id WHERE $where ORDER BY a.id DESC");
    $countWhere=$currentRole==='admin'?'1=1':'assigned_staff_id='.$staffId;
    $loanPending=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Pending' AND $countWhere");$loanForwarded=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Forwarded' AND $countWhere");$loanApproved=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Approved' AND $countWhere");$loanRejected=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE status='Rejected' AND $countWhere");$loanTotal=$loanPending+$loanForwarded+$loanApproved+$loanRejected;
    $staffOptions=[]; if($currentRole==='admin'){$sr=$db->query("SELECT id,username,display_name FROM users WHERE role='staff' ORDER BY display_name,username");while($sx=$sr->fetchArray(SQLITE3_ASSOC))$staffOptions[]=$sx;}
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">MEMBER REQUESTS</div><h1>Loan Applications</h1><p><?= $currentRole==='staff' ? 'Staff reviews the application, adds remarks and forwards it to Admin. <span class="hi-sub">स्टाफ आवेदन की समीक्षा करके टिप्पणी के साथ एडमिन को भेजता है।</span>' : 'Admin सभी आवेदन देख सकता है, Staff assignment बदल सकता है और forwarded आवेदन मंज़ूर/रिजेक्ट कर सकता है। <span class="hi-sub">एडमिन सभी आवेदन देख सकता है।</span>' ?></p></div><a class="btn" href="?route=notifications">🔔 Notifications (<?=notificationCount()?>)</a></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="kpis loan-summary"><div class="kpi orange"><span>Staff Pending</span><b><?=$loanPending?></b><small>Needs Staff review</small></div><div class="kpi purple"><span>Forwarded</span><b><?=$loanForwarded?></b><small>Waiting for Admin</small></div><div class="kpi green"><span>Approved</span><b><?=$loanApproved?></b><small>Approved applications</small></div><div class="kpi blue"><span>Total</span><b><?=$loanTotal?></b><small>All applications</small></div></div><div class="panel"><div class="table-wrap"><table><thead><tr><th>Member</th><th>Deposit</th><th>Requested</th><th>Tenure</th><th>Purpose</th><th>Assigned Staff</th><th>Staff Remarks</th><th>Bank / Transfer Details</th><th>Status / Action</th></tr></thead><tbody><?php while($a=$apps->fetchArray(SQLITE3_ASSOC)): ?><tr><td><b><?=h($a['name'])?></b><small class="block"><?=h($a['code'])?></small></td><td><?=money((float)$a['deposit'])?></td><td><?=money((float)$a['requested'])?></td><td><?=h((string)$a['tenure'])?> mo</td><td><?=h($a['purpose'])?></td><td><?php if($currentRole==='admin'): ?><form method="post" class="inline-form"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="id" value="<?=$a['id']?>"><select name="assigned_staff_id"><option value="0">Unassigned</option><?php foreach($staffOptions as $so): ?><option value="<?=$so['id']?>" <?=((int)($a['assigned_staff_id']??0)===(int)$so['id'])?'selected':''?>><?=h(($so['display_name']?:$so['username']))?></option><?php endforeach; ?></select><input name="assignment_reason" placeholder="Reason (optional)" maxlength="200"><button class="btn small" name="action" value="assign_staff">Assign</button></form><?php else: ?><b><?=h($a['assigned_staff_name'])?></b><?php endif; ?></td><td><?=h($a['staff_remark']?:'—')?></td><td><small><b><?=h($a['bank_name']?:'—')?></b><br><?=h($a['account_holder']?:'—')?><br>AC: <?=h($a['account_number']?:'—')?><br>IFSC: <?=h($a['ifsc']?:'—')?><?php if(!empty($a['bank_upi_id'])): ?><br>UPI: <?=h($a['bank_upi_id'])?><?php endif; ?></small></td><td><span class="badge <?=strtolower($a['status'])==='approved'?'success':(strtolower($a['status'])==='rejected'?'danger':(strtolower($a['status'])==='forwarded'?'info':'warning'))?>"><?=h($a['status'])?></span><?php if($currentRole==='staff' && $a['status']==='Pending'): ?><form class="inline-form" method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="id" value="<?=$a['id']?>"><input name="note" placeholder="Staff remarks" required><button class="btn small primary" name="action" value="forward">Review & Forward</button></form><?php elseif($currentRole==='admin' && $a['status']==='Forwarded'): ?><form class="inline-form" method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="id" value="<?=$a['id']?>"><input name="approved_amount" type="number" step="0.01" value="<?=h((string)$a['requested'])?>" placeholder="Amount"><input name="interest_rate" type="number" step="0.01" value="12" placeholder="%"><input name="note" placeholder="Admin remarks"><button class="btn small primary" name="action" value="approve">Approve</button><button class="btn small danger" name="action" value="reject">Reject</button></form><?php endif; ?></td></tr><?php endwhile; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('Loan Applications',$c); exit;
}

if($route==='member-loan-apply'){
    requireRole(['member']); $m=memberOfUser(); $deposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=".(int)$m['id']." AND status='Paid'");$limit=$deposit*(float)getSetting('loan_eligibility_percent','80')/100;$msg='';$msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $amount=(float)($_POST['requested']??0);$tenure=(int)($_POST['tenure']??0);$purpose=trim($_POST['purpose']??'');$note=trim($_POST['note']??'');
        $bankName=trim($_POST['bank_name']??'');$accountHolder=trim($_POST['account_holder']??'');$accountNumber=preg_replace('/\D+/','',trim($_POST['account_number']??''));$ifsc=strtoupper(trim($_POST['ifsc']??''));$bankUpi=trim($_POST['bank_upi_id']??'');
        if(($m['status']??'')!=='Active'){$msg='Closed member accounts cannot apply for a new loan.';$msgType='warning';}
        elseif($amount<=0||$amount>$limit){$msg='Requested amount exceeds your current eligible loan limit.';$msgType='danger';}
        elseif($accountHolder===''||$accountNumber===''||strlen($accountNumber)<6||$ifsc===''||!preg_match('/^[A-Z]{4}0[A-Z0-9]{6}$/',$ifsc)){ $msg='Please enter valid bank account holder, account number and IFSC. / कृपया सही बैंक विवरण भरें।';$msgType='danger';}
        elseif($tenure<1||$tenure>120){$msg='Invalid tenure. Choose 1 to 120 months.';$msgType='danger';}
        elseif($purpose===''){$msg='Please enter the loan purpose.';$msgType='danger';}
        else{
            $pending=(int)$db->querySingle("SELECT COUNT(*) FROM loan_applications WHERE member_id=".(int)$m['id']." AND status='Pending'");
            if($pending>0){$msg='You already have a pending loan application. Please wait for Admin review.';$msgType='warning';}
            else{
                $st=$db->prepare("UPDATE members SET bank_name=?,account_holder=?,account_number=?,ifsc=?,bank_upi_id=? WHERE id=?");
                $st->bindValue(1,$bankName,SQLITE3_TEXT);$st->bindValue(2,$accountHolder,SQLITE3_TEXT);$st->bindValue(3,$accountNumber,SQLITE3_TEXT);$st->bindValue(4,$ifsc,SQLITE3_TEXT);$st->bindValue(5,$bankUpi,SQLITE3_TEXT);$st->bindValue(6,(int)$m['id'],SQLITE3_INTEGER);$st->execute();
                $assignedStaff=(int)$db->querySingle("SELECT staff_id FROM staff_member_assignments WHERE member_id=".(int)$m['id']." ORDER BY assigned_at DESC,id DESC LIMIT 1");
                $st=$db->prepare("INSERT INTO loan_applications(member_id,requested,tenure,purpose,note,assigned_staff_id) VALUES(?,?,?,?,?,?)");
                $st->bindValue(1,(int)$m['id'],SQLITE3_INTEGER);$st->bindValue(2,$amount,SQLITE3_FLOAT);$st->bindValue(3,$tenure,SQLITE3_INTEGER);$st->bindValue(4,$purpose,SQLITE3_TEXT);$st->bindValue(5,$note,SQLITE3_TEXT);$st->bindValue(6,$assignedStaff>0?$assignedStaff:null,$assignedStaff>0?SQLITE3_INTEGER:SQLITE3_NULL);
                if($st->execute()){$m['bank_name']=$bankName;$m['account_holder']=$accountHolder;$m['account_number']=$accountNumber;$m['ifsc']=$ifsc;$m['bank_upi_id']=$bankUpi;$msg='Loan application submitted. Staff will review it first and then forward it to Admin.'; if(getSetting('whatsapp_auto_loan_application_enabled','0')==='1'){ $mm=['id'=>$m['id'],'name'=>$m['name'],'mobile'=>$m['mobile'],'code'=>$m['code']]; $wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'loan_application',['amount'=>number_format($amount,2),'purpose'=>$purpose])); if(!$wr[0])$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1]; }}else{$msg='Loan application could not be submitted. Please try again.';$msgType='danger';}
            }
        }
    }
    $apps=$db->query("SELECT * FROM loan_applications WHERE member_id=".$m['id']." ORDER BY id DESC");
    ob_start(); ?><div class="page-title modern-form-title"><div><div class="eyebrow">LOAN REQUEST</div><h1>Apply for Loan</h1><p>Your deposit: <b><?=money($deposit)?></b> · Eligible limit: <b><?=money($limit)?></b></p></div></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
<div class="modern-form-kpis">
  <div class="modern-form-kpi"><span>My Deposit</span><b><?=money($deposit)?></b></div>
  <div class="modern-form-kpi green"><span>Eligible Loan</span><b><?=money($limit)?></b></div>
</div>
<div class="grid-2 modern-form-grid"><div class="panel modern-form-panel"><div class="panel-head"><h2>Loan Application</h2><span class="badge info">Member</span></div><form method="post" class="modern-form"><input type="hidden" name="csrf" value="<?=h(csrf())?>">
<div class="modern-form-row"><label>Requested Amount (₹)</label><input id="loanAmount" type="number" step="0.01" max="<?=h((string)$limit)?>" name="requested" placeholder="Enter amount" required></div>
<div class="modern-form-row two-col"><div><label>Tenure (months)</label><input id="tenure" type="number" min="1" max="120" name="tenure" value="12" required></div><div><label>Purpose</label><input name="purpose" placeholder="e.g. Business, Education" required></div></div>
<div class="modern-form-section">Bank Details / बैंक विवरण</div>
<div class="modern-form-row"><label>Bank Name / बैंक का नाम</label><input name="bank_name" value="<?=h($m['bank_name']??'')?>" required></div>
<div class="modern-form-row two-col"><div><label>Account Holder / खाताधारक</label><input name="account_holder" value="<?=h($m['account_holder']??$m['name'])?>" required></div><div><label>Account Number / खाता नंबर</label><input name="account_number" value="<?=h($m['account_number']??'')?>" inputmode="numeric" required></div></div>
<div class="modern-form-row two-col"><div><label>IFSC / आईएफएससी</label><input name="ifsc" value="<?=h($m['ifsc']??'')?>" maxlength="11" style="text-transform:uppercase" required></div><div><label>UPI ID (optional)</label><input name="bank_upi_id" value="<?=h($m['bank_upi_id']??'')?>" placeholder="name@upi"></div></div>
<div class="modern-form-row"><label>Note</label><textarea name="note" placeholder="Additional details (optional)"></textarea></div>
<div class="modern-emi-box">Estimated EMI @ 12%: <b id="emi">₹0.00</b></div>
<button class="btn primary full modern-submit">Submit Application</button></form></div><div class="panel modern-form-panel"><div class="panel-head"><h2>My Applications</h2></div><?php while($a=$apps->fetchArray(SQLITE3_ASSOC)): ?><div class="application"><div><b><?=money((float)$a['requested'])?></b><span><?=h($a['tenure'])?> months · <?=h($a['purpose'])?></span></div><span class="badge <?=strtolower($a['status'])==='approved'?'success':(strtolower($a['status'])==='rejected'?'danger':(strtolower($a['status'])==='forwarded'?'info':'warning'))?>"><?=h($a['status']==='Pending'?'Staff Review':($a['status']==='Forwarded'?'Admin Review':$a['status']))?></span><?php if(!empty($a['staff_remark'])): ?><small class="block muted">Staff: <?=h($a['staff_remark'])?></small><?php endif; ?></div><?php endwhile; ?></div></div><script>function calc(){let p=+document.getElementById('loanAmount').value||0,n=+document.getElementById('tenure').value||1,r=.12/12;let e=r? p*r*Math.pow(1+r,n)/(Math.pow(1+r,n)-1):p/n;document.getElementById('emi').textContent='₹'+e.toFixed(2)}document.getElementById('loanAmount').addEventListener('input',calc);document.getElementById('tenure').addEventListener('input',calc);</script><?php $c=ob_get_clean(); layout('Apply Loan',$c); exit;
}

if($route==='member-pay'){
    requireRole(['member']); $m=memberOfUser(); $due=(float)getSetting('monthly_contribution','0');$month=date('Y-m');$paid=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=".$m['id']." AND month='".SQLite3::escapeString($month)."' AND status='Paid'");$amount=max(0,$due-$paid);$msg='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $amt=(float)($_POST['amount']??0); $txn=trim((string)($_POST['payment_utr']??''));
        if($amt<=0) $msg='कृपया सही भुगतान राशि दर्ज करें।';
        elseif($amt>$amount+0.01) $msg='भुगतान राशि बाकी योगदान से अधिक नहीं हो सकती।';
        elseif($txn==='') $msg='UPI ऐप की Transaction Details से UTR / Transaction ID भरें।';
        elseif(strlen($txn)>100) $msg='UTR / Transaction ID 100 अक्षरों से छोटा होना चाहिए।';
        else {
            $dupe=$db->prepare("SELECT (SELECT COUNT(*) FROM contributions WHERE LOWER(txn_id)=LOWER(?) AND txn_id!='') + (SELECT COUNT(*) FROM payments WHERE LOWER(txn_id)=LOWER(?) AND txn_id!='')"); $dupe->bindValue(1,$txn); $dupe->bindValue(2,$txn); $exists=(int)$dupe->execute()->fetchArray(SQLITE3_NUM)[0];
            if($exists>0) $msg='यह UTR / Transaction ID पहले दर्ज हो चुकी है। कृपया सही Transaction ID जाँचें।';
            else { $st=$db->prepare("INSERT INTO contributions(member_id,amount,month,mode,status,txn_id,created_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)");$st->bindValue(1,$m['id']);$st->bindValue(2,$amt);$st->bindValue(3,$month);$st->bindValue(4,'Online UPI');$st->bindValue(5,'Pending');$st->bindValue(6,$txn); if($st->execute()) $msg="भुगतान अनुरोध दर्ज हो गया। UTR: $txn — Admin/Staff बैंक में जाँचकर Verify करेंगे।"; else $msg='भुगतान अनुरोध दर्ज नहीं हो पाया। कृपया दोबारा प्रयास करें।'; }
        }
    }
    $link=upiExternalIntentLink($amount);$qr='https://quickchart.io/qr?size=300&text='.rawurlencode(upiLink($amount));
    ob_start(); ?>
    <div class="pb-checkout">
      <div class="pb-heading"><div><span class="pb-eyebrow">GS SURAHA FINANCE · SECURE PAYMENTS</span><h1>Pay Contribution</h1><p>Complete your monthly contribution securely.</p></div><span class="pb-lock">♙ Secure</span></div>
      <?php if($msg): ?><div class="alert <?=((strpos($msg,'दर्ज हो गया')!==false)?'success':((strpos($msg,'दर्ज नहीं')!==false||strpos($msg,'पहले दर्ज')!==false||strpos($msg,'भरें')!==false||strpos($msg,'छोटा होना')!==false||strpos($msg,'सही भुगतान')!==false||strpos($msg,'अधिक नहीं')!==false)?'danger':'info'))?>"><?=h($msg)?></div><?php endif; ?>
      <div class="pb-member-identity"><span class="pb-member-mark" aria-hidden="true">GS</span><div><b><?=h((string)($m['name']??'Member'))?></b><small>Member ID: <?=h((string)($m['code']??'—'))?></small></div><span class="pb-demo-tag">MEMBER</span></div>
      <section class="pb-total-card"><div class="pb-total-top"><span>AMOUNT TO PAY</span><span class="pb-status"><i></i> <?= $amount>0?'Payment due':'Up to date' ?></span></div><div class="pb-amount"><?=money($amount)?></div><div class="pb-total-foot"><span><?=h(date('F Y'))?> contribution</span><span>Secure UPI payment</span></div><div class="pb-progress"><span style="width:<?=h((string)($due>0?min(100,($paid/$due)*100):100))?>%"></span></div><div class="pb-breakdown"><div><small>Monthly contribution</small><b><?=money($due)?></b></div><div><small>Already paid</small><b><?=money($paid)?></b></div><div><small>Remaining</small><b><?=money($amount)?></b></div></div></section>
      <?php if($amount>0): ?>
      <section class="pb-payment-card"><div class="pb-section-title"><span class="pb-step">01</span><div><h2>Choose your payment method</h2><p>Fast, simple and secure UPI payment</p></div></div>
        <?php if(getSetting('upi_id')!==''): ?>
        <div class="pb-method"><div class="pb-method-icon">↗</div><div class="pb-method-copy"><b>UPI Payment</b><small>PhonePe · Google Pay · Paytm · BHIM</small></div><span class="pb-recommended">RECOMMENDED</span></div>
        <div class="pb-pay-actions"><a class="pb-upi-button" id="contributionPayNow" target="_blank" rel="noopener noreferrer" href="<?=h($link)?>" data-upi-plain="<?=h(upiLink($amount))?>" data-upi-intent="<?=h($link)?>" onclick="revealPaymentSubmit('contributionSubmitWrap'); if(!/Android/i.test(navigator.userAgent)){this.href=this.getAttribute('data-upi-plain');}"><span>↗</span> Open UPI App <b>→</b></a>
        <p class="muted" style="font-size:12px;margin:8px 0 0;line-height:1.45">App ke andar payment fail ho to ye button <b>PhonePe / Google Pay / Paytm</b> alag app mein kholega. Agar phir bhi app ke andar hi khule to browser (Chrome) se login karke pay karein, ya app settings mein UPI / external links allow karein.</p><?php if(getSetting('payment_api_url')!==''): ?><a class="pb-gateway-link" target="_blank" rel="noopener" href="<?=h(getSetting('payment_api_url'))?>?amount=<?=rawurlencode((string)$amount)?>&member_id=<?=rawurlencode((string)$m['id'])?>&type=contribution&month=<?=rawurlencode($month)?>&return_url=<?=rawurlencode(siteBaseUrl().'?route=payment-api-callback')?>">Pay using payment gateway →</a><?php endif; ?></div>
        <details class="pb-qr-details"><summary><span class="pb-qr-summary-icon">▦</span><span><b>Scan & Pay using QR</b><small>Tap to show your payment QR code</small></span><strong class="pb-qr-chevron">＋</strong></summary><div class="pb-qr-area"><button class="pb-qr-frame gs-qr-open" type="button" data-qr="<?=h($qr)?>" aria-label="Open payment QR code larger" onclick="openPaymentQr(this.getAttribute('data-qr'))"><img src="<?=h($qr)?>" alt="UPI payment QR code"></button><div class="pb-qr-copy"><b>Scan & Pay</b><p>Open any UPI app, scan this QR code and pay <strong><?=money($amount)?></strong>.</p><small>UPI ID<br><strong><?=h(getSetting('upi_id'))?></strong></small></div></div></details>
        <?php else: ?><div class="alert warning">Admin has not configured the UPI ID yet.</div><?php endif; ?>
      </section>
      <section class="pb-confirm-card"><div class="pb-section-title"><span class="pb-step">02</span><div><h2>Confirm your payment</h2><p>Submit transaction details after paying</p></div></div><button type="button" class="pb-outline-button" onclick="revealPaymentSubmit('contributionSubmitWrap')">I have completed the payment <span>↓</span></button><div id="contributionSubmitWrap" hidden><div class="pb-note">Please enter the UTR / Transaction ID shown in your UPI app. Your payment will remain pending until verified by the office.</div><form method="post" class="pb-form"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><label>Payment amount (₹)</label><input type="number" name="amount" step="0.01" min="1" max="<?=h((string)$amount)?>" value="<?=h((string)max(1,$amount))?>" required><label>UTR / Transaction ID</label><input type="text" name="payment_utr" maxlength="100" placeholder="Enter 12-digit UTR / Transaction ID" autocomplete="off" required><small>Find this in Transaction Details in PhonePe, Google Pay or Paytm. A UTR can only be used once.</small><button class="pb-submit-button">Submit for verification <span>→</span></button></form></div></section>
      <?php else: ?><div class="pb-paid-state"><span>✓</span><h2>You are all caught up!</h2><p>Your contribution for this month has been paid.</p><a href="?route=member-payment-history">View payment history →</a></div><?php endif; ?>
      <div class="pb-trust"><span>♧</span><div><b>Your payment details are protected</b><small>Never share your UPI PIN or OTP with anyone. GS Suraha staff will verify your transaction.</small></div></div>
      <dialog id="paymentQrModal" class="gs-qr-dialog gs-qr-native" aria-label="Payment QR code" onclick="if(event.target===this)closePaymentQr()" onclose="document.getElementById('paymentQrLarge').src=''"><button type="button" class="gs-qr-close" aria-label="Close QR code" onclick="closePaymentQr()">×</button><h2>Scan &amp; Pay</h2><img id="paymentQrLarge" src="" alt="Enlarged UPI payment QR code"><p>Open your UPI app and scan this QR code.</p></dialog>
    </div>
    <script>function revealPaymentSubmit(id){var el=document.getElementById(id);if(el){el.hidden=false;el.scrollIntoView({behavior:'smooth',block:'nearest'});}}function openPaymentQr(src){var modal=document.getElementById('paymentQrModal'),img=document.getElementById('paymentQrLarge');if(!modal||!img)return;img.src=src;if(typeof modal.showModal==='function'){if(!modal.open)modal.showModal();}else{modal.setAttribute('open','');}}function closePaymentQr(){var modal=document.getElementById('paymentQrModal'),img=document.getElementById('paymentQrLarge');if(modal&&modal.open)modal.close();else if(modal)modal.removeAttribute('open');if(img)img.src='';}if(window.matchMedia&&window.matchMedia('(max-width:600px)').matches){var mobileQr=document.querySelector('.pb-qr-details');if(mobileQr)mobileQr.open=true;}</script>
    <?php $c=ob_get_clean(); layout('Online Payment',$c); exit;
}

if($route==='member-emi-pay'){
    requireRole(['member']); $m=memberOfUser(); $mid=(int)$m['id']; $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $emiId=(int)($_POST['emi_id']??0); $amount=(float)($_POST['amount']??0);
        $st=$db->prepare("SELECT e.*,l.member_id,l.id loan_id FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE e.id=? AND l.member_id=?");$st->bindValue(1,$emiId);$st->bindValue(2,$mid);$e=$st->execute()->fetchArray(SQLITE3_ASSOC);
        if(!$e){$msg='EMI not found.';$msgType='danger';}
        elseif($e['status']==='Paid' || (float)$e['paid_amount'] >= (float)$e['amount']){$msg='This EMI is already paid.';$msgType='warning';}
        else{$due=max(0,(float)$e['amount']-(float)$e['paid_amount']); $txn=trim((string)($_POST['payment_utr']??'')); if($amount<=0||$amount>$due+0.01){$msg='Enter a valid EMI amount up to '.money($due).'.';$msgType='danger';}elseif($txn===''){$msg='UPI ऐप की Transaction Details से UTR / Transaction ID भरें।';$msgType='danger';}elseif(strlen($txn)>100){$msg='UTR / Transaction ID 100 अक्षरों से छोटा होना चाहिए।';$msgType='danger';}else{$dupe=$db->prepare("SELECT (SELECT COUNT(*) FROM contributions WHERE LOWER(txn_id)=LOWER(?) AND txn_id!='') + (SELECT COUNT(*) FROM payments WHERE LOWER(txn_id)=LOWER(?) AND txn_id!='')");$dupe->bindValue(1,$txn);$dupe->bindValue(2,$txn);$exists=(int)$dupe->execute()->fetchArray(SQLITE3_NUM)[0];if($exists>0){$msg='यह UTR / Transaction ID पहले दर्ज हो चुकी है। कृपया सही Transaction ID जाँचें।';$msgType='danger';}else{$st=$db->prepare("INSERT INTO payments(member_id,loan_id,emi_id,amount,mode,txn_id,status) VALUES(?,?,?,?,?,?,?)");$st->bindValue(1,$mid);$st->bindValue(2,(int)$e['loan_id']);$st->bindValue(3,$emiId);$st->bindValue(4,$amount);$st->bindValue(5,'Online UPI');$st->bindValue(6,$txn);$st->bindValue(7,'Pending');if($st->execute()){$msg="EMI भुगतान अनुरोध दर्ज हो गया। UTR: $txn — Admin/Staff बैंक में जाँचकर Verify करेंगे.";}else{$msg='EMI payment could not be submitted.';$msgType='danger';}}}}
    }
    $emis=$db->query("SELECT e.*,l.id loan_id,l.principal FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE l.member_id=$mid AND e.status!='Paid' ORDER BY e.due_date ASC");
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">LOAN REPAYMENT</div><h1>Pay EMI</h1><p>Choose an EMI and pay by UPI app or QR. <span class="hi-sub">ईएमआई चुनें और UPI ऐप या QR से भुगतान करें।</span></p></div></div><div class="pb-member-identity"><span class="pb-member-mark" aria-hidden="true">GS</span><div><b><?=h((string)($m['name']??'Member'))?></b><small>Member ID: <?=h((string)($m['code']??'—'))?></small></div><span class="pb-demo-tag">MEMBER</span></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="grid-2"><div class="panel"><h2>Pending EMIs</h2><?php $has=false; while($e=$emis->fetchArray(SQLITE3_ASSOC)): $has=true; $due=max(0,(float)$e['amount']-(float)$e['paid_amount']); $emiLink=upiExternalIntentLink($due,'EMI-'.$e['id'].'-'.date('YmdHis')); $emiQr='https://quickchart.io/qr?size=300&text='.rawurlencode(upiLink($due,'EMI-'.$e['id'].'-'.date('YmdHis'))); ?><div class="emi-pay-row emi-pay-row-modern"><div class="emi-info"><div><b>EMI #<?=h((string)$e['installment_no'])?></b><span>Due <?=h($e['due_date'])?> · <?=money((float)$e['amount'])?></span></div><span class="badge <?=($e['due_date']<=date('Y-m-d'))?'danger':'warning'?>"><?=h($e['status'])?></span></div><div class="emi-payment-box"><?php if(getSetting('upi_id')!==''): ?><a class="btn small" target="_blank" rel="noopener noreferrer" href="<?=h($emiLink)?>" data-upi-plain="<?=h(upiLink($due,'EMI-'.$e['id'].'-'.date('YmdHis')))?>" data-upi-intent="<?=h($emiLink)?>" onclick="revealPaymentSubmit('emiSubmitWrap<?=$e['id']?>'); if(!/Android/i.test(navigator.userAgent)){this.href=this.getAttribute('data-upi-plain');}">📱 Open UPI App (optional)</a><?php if(getSetting('payment_api_url')!==''): ?><a class="btn small" target="_blank" rel="noopener" href="<?=h(getSetting('payment_api_url'))?>?amount=<?=rawurlencode((string)$due)?>&member_id=<?=rawurlencode((string)$mid)?>&emi_id=<?=rawurlencode((string)$e['id'])?>&type=emi&return_url=<?=rawurlencode(siteBaseUrl().'?route=payment-api-callback')?>">🌐 Pay via API</a><?php endif; ?><details class="emi-qr-details"><summary>▣ Show QR Code</summary><div class="emi-qr-wrap"><button class="gs-qr-open gs-qr-open-emi" type="button" data-qr="<?=h($emiQr)?>" aria-label="Open EMI QR code larger" onclick="openPaymentQr(this.getAttribute('data-qr'))"><img src="<?=h($emiQr)?>" alt="UPI QR for EMI payment"></button><small>Scan with any UPI app · <?=h(getSetting('upi_id'))?></small></div></details><?php else: ?><div class="alert warning">Admin has not configured the UPI ID yet.</div><?php endif; ?><button type="button" class="btn small" style="margin-top:8px" onclick="revealPaymentSubmit('emiSubmitWrap<?=$e['id']?>')">✓ भुगतान कर दिया? Submit करें</button><div id="emiSubmitWrap<?=$e['id']?>" hidden><div class="alert info">UPI भुगतान पूरा होने के बाद ही Submit करें। UTR दर्ज करना अनिवार्य है।</div><form method="post" class="emi-pay-form"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="emi_id" value="<?=$e['id']?>"><label>भुगतान राशि</label><input name="amount" type="number" step="0.01" min="1" max="<?=h((string)$due)?>" value="<?=h((string)$due)?>" required><label>UTR / Transaction ID <span class="muted">(अनिवार्य)</span></label><input type="text" name="payment_utr" maxlength="100" placeholder="UPI ऐप से UTR भरें" autocomplete="off" required><small class="muted">एक ही UTR दो बार स्वीकार नहीं होगा।</small><button class="btn small primary full">Submit EMI for Verification</button></form></div></div></div><?php endwhile; if(!$has): ?><div class="alert success">No pending EMI. All current EMIs are paid.</div><?php endif; ?></div><div class="panel"><h2>EMI Payment Note</h2><p class="muted">Recommended: scan the QR code from your UPI app. If opening the UPI link launches Paytm and shows a risk warning, cancel and use QR scanning instead. Online EMI payments remain <b>Pending</b> until Admin/Staff verifies the transaction. Your loan balance is updated only after verification.</p><div class="payment-methods-note"><span>📱 UPI App</span><span>▣ QR Code</span><span>🔐 Verification</span></div><a class="btn" href="?route=notifications">🔔 View Notifications</a></div></div><dialog id="paymentQrModal" class="gs-qr-dialog gs-qr-native" aria-label="EMI payment QR code" onclick="if(event.target===this)closePaymentQr()" onclose="document.getElementById('paymentQrLarge').src=''"><button type="button" class="gs-qr-close" aria-label="Close QR code" onclick="closePaymentQr()">×</button><h2>Scan &amp; Pay EMI</h2><img id="paymentQrLarge" src="" alt="Enlarged UPI EMI QR code"><p>Open your UPI app and scan this QR code.</p></dialog><script>function revealPaymentSubmit(id){var el=document.getElementById(id);if(el){el.hidden=false;el.scrollIntoView({behavior:'smooth',block:'nearest'});}}function openPaymentQr(src){var modal=document.getElementById('paymentQrModal'),img=document.getElementById('paymentQrLarge');if(!modal||!img)return;img.src=src;if(typeof modal.showModal==='function'){if(!modal.open)modal.showModal();}else{modal.setAttribute('open','');}}function closePaymentQr(){var modal=document.getElementById('paymentQrModal'),img=document.getElementById('paymentQrLarge');if(modal&&modal.open)modal.close();else if(modal)modal.removeAttribute('open');if(img)img.src='';}</script><?php $c=ob_get_clean(); layout('Pay EMI',$c); exit;
}

if($route==='member-close-request'){
    requireRole(['member']); $m=memberOfUser(); if(!$m) exit('Member not found.'); $msg=''; $msgType='success';
    $existing=$db->prepare("SELECT * FROM member_closures WHERE member_id=? AND status='Pending' ORDER BY id DESC LIMIT 1"); $existing->bindValue(1,(int)$m['id'],SQLITE3_INTEGER); $existing=$existing->execute()->fetchArray(SQLITE3_ASSOC);
    $contrib=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=".(int)$m['id']." AND status='Paid'");
    $pool=(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections"); $exitMethod=(string)getSetting('member_exit_interest_method','A'); $interest=gsMemberExitInterestShare($db,(int)$m['id'],$exitMethod); $refund=round($contrib+$interest,2);
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); if($existing) $msg='A closure request is already pending Admin approval.'; elseif(($m['status']??'Active')==='Closed') $msg='Your Member ID is already closed.';
        elseif($contrib<=0) $msg='No paid contribution balance is available for closure.';
        else { $reason=trim((string)($_POST['reason']??'Member requested account closure')); $q=$db->prepare("INSERT INTO member_closures(member_id,contribution_total,interest_pool,member_interest,deductions,refund_amount,reason,status,approved_by,requested_by,requested_at) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)"); $vals=[$m['id'],$contrib,$pool,$interest,0,$refund,$reason,'Pending',null,$m['id']]; foreach($vals as $i=>$v) $q->bindValue($i+1,$v, is_int($v)?SQLITE3_INTEGER:SQLITE3_TEXT); $q->execute(); $msg='Closure/refund request Admin को भेज दी गई है। Approval के बाद Member ID बंद होगी और refund report में record बनेगा.'; $existing=['refund_amount'=>$refund]; }
    }
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ACCOUNT CLOSURE</div><h1>Close Member ID</h1><p>अपना Member ID बंद करने के लिए refund request भेजें। Admin approval के बाद account close होगा।</p></div><a class="btn" href="?route=member-dashboard">← Dashboard</a></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="grid-2"><div class="panel"><h2>Refund Calculation</h2><div class="profile-grid"><div><b>My Contribution</b><span><?=money($contrib)?></span></div><div><b>Total Loan Interest Collected</b><span><?=money($pool)?></span></div><div><b>My Interest Earned</b><span><?=money($interest)?></span></div><div><b>Estimated Refund</b><span><strong><?=money($refund)?></strong></span></div></div><div class="alert info"><b>लागू ब्याज-वितरण तरीका:</b> <?=($exitMethod==='B'?'B — जमा राशि × समिति में रहने के महीने':'A — कुल जमा राशि के अनुपात में')?>।<br><b>A:</b> कुल जमा के अनुपात में हिस्सा। <b>B:</b> जमा राशि और जमा रहने की अवधि दोनों के अनुपात में हिस्सा। केवल वास्तव में वसूला गया लोन ब्याज शामिल है।</div></div><div class="panel"><h2>Submit Closure Request</h2><?php if($existing): ?><div class="alert warning">Closure request pending है. Estimated refund: <b><?=money((float)$existing['refund_amount'])?></b></div><?php else: ?><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><label>Reason / कारण</label><textarea name="reason" rows="4" placeholder="Why do you want to close your Member ID?"></textarea><button class="btn danger full" style="margin-top:12px" onclick="return confirm('Closure request भेजें? Account तुरंत close नहीं होगा; Admin approval के बाद close होगा.')">🔒 Request Member ID Closure</button></form><?php endif; ?></div></div><?php $c=ob_get_clean(); layout('Close Member ID',$c); exit;
}

if($route==='member-financial-summary'){
    requireRole(['member']); $m=memberOfUser();
    if(!$m){ http_response_code(200); ob_start(); ?><div class="panel"><h2>Member profile link nahi mila</h2><p>Admin से Member ID mapping जाँच करवाएँ।</p></div><?php $c=ob_get_clean(); layout('My Financial Summary',$c); exit; }
    $mid=(int)$m['id']; $deposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id={$mid} AND status='Paid'"); $allDeposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'"); $interest=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger WHERE member_id={$mid}"); $refund=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE member_id={$mid} AND status='Approved'"); $available=($m['status']??'')==='Closed'?0:max(0,round($deposit+$interest-$refund,2)); $societyLoans=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans WHERE status='Active'");
    $societyActiveMembers=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");
    $societyPaidThisMonth=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid' AND month='".SQLite3::escapeString(date('Y-m'))."'");
    $societyMembersPaidThisMonth=(int)$db->querySingle("SELECT COUNT(DISTINCT member_id) FROM contributions WHERE status='Paid' AND month='".SQLite3::escapeString(date('Y-m'))."'");
    $societyMonthlyExpected=$societyActiveMembers*(float)getSetting('monthly_contribution','0');
    $societyPendingThisMonth=max(0,$societyMonthlyExpected-$societyPaidThisMonth);
    $societyActiveLoanCount=(int)$db->querySingle("SELECT COUNT(*) FROM loans WHERE status='Active'");
    $societyApprovedRefund=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE status='Approved'");
    ob_start(); ?>
    <div class="ml-page mfs-page">
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">📊</div>
          <div>
            <h1>My Financial Summary</h1>
            <p>केवल आपके खाते की जानकारी · <?=h($m['code']??'')?></p>
          </div>
        </div>
        <a class="ml-btn-add" href="?route=member-dashboard">← Dashboard</a>
      </div>

      <div class="ml-stats mfs-stats">
        <div class="ml-stat green"><div class="ml-stat-icon">✓</div><div><span>Available Balance</span><b><?=money($available)?></b></div></div>
        <div class="ml-stat blue"><div class="ml-stat-icon">₹</div><div><span>Total Deposit</span><b><?=money($deposit)?></b></div></div>
        <div class="ml-stat purple"><div class="ml-stat-icon">📈</div><div><span>Interest Earned</span><b><?=money($interest)?></b></div></div>
        <div class="ml-stat orange"><div class="ml-stat-icon">↩</div><div><span>Approved Refund</span><b><?=money($refund)?></b></div></div>
      </div>

      <div class="md-grid mfs-grid">
        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">👤</span><h2>Personal Snapshot</h2></div>
          <div class="md-detail-list">
            <div><small>Member ID</small><b><?=h($m['code']??'—')?></b></div>
            <div><small>Name</small><b><?=h($m['name']??'—')?></b></div>
            <div><small>Status</small><b><?=h($m['status']??'—')?></b></div>
            <div><small>Mobile</small><b><?=h($m['mobile']??'—')?></b></div>
          </div>
        </section>
        <section class="md-card">
          <div class="md-card-head"><span class="md-card-icon">💰</span><h2>Account Formula</h2></div>
          <div class="md-detail-list">
            <div><small>Deposit</small><b><?=money($deposit)?></b></div>
            <div><small>+ Interest</small><b><?=money($interest)?></b></div>
            <div><small>− Refund</small><b><?=money($refund)?></b></div>
            <div><small>= Available</small><b class="mb-available"><?=money($available)?></b></div>
          </div>
        </section>
      </div>

    <section class="society-overview-modern mfs-society">
      <div class="mfs-society-head">
        <div>
          <div class="mfs-eyebrow">SOCIETY OVERVIEW</div>
          <h2>समिति का कुल (Samiti Total)</h2>
          <p>पूरी समिति का सारांश — आपके व्यक्तिगत खाते से अलग।</p>
        </div>
        <span class="mfs-month"><?=h(date('F Y'))?></span>
      </div>
      <div class="mfs-society-grid">
        <div class="mfs-society-card"><small>👥 सक्रिय सदस्य</small><div class="mfs-num"><?=number_format($societyActiveMembers)?></div></div>
        <div class="mfs-society-card"><small>💳 समिति में कुल जमा</small><div class="mfs-num"><?=money($allDeposit)?></div><small class="mfs-sub">Paid Contribution (all time)</small></div>
        <div class="mfs-society-card"><small>✅ इस माह जमा करने वाले</small><div class="mfs-num"><?=number_format($societyMembersPaidThisMonth)?></div><small class="mfs-sub">कुल सक्रिय सदस्यों में से</small></div>
        <div class="mfs-society-card"><small>⏳ इस माह Pending जमा</small><div class="mfs-num"><?=money($societyPendingThisMonth)?></div><small class="mfs-sub">मासिक लक्ष्य − Paid जमा</small></div>
        <div class="mfs-society-card"><small>🏦 सक्रिय लोन मूल राशि</small><div class="mfs-num"><?=money($societyLoans)?></div><small class="mfs-sub"><?=number_format($societyActiveLoanCount)?> सक्रिय लोन</small></div>
        <div class="mfs-society-card"><small>↩️ मंजूर कुल Refund</small><div class="mfs-num"><?=money($societyApprovedRefund)?></div></div>
      </div>
      <p class="mfs-note">Pending राशि का अनुमान सक्रिय सदस्यों × निर्धारित मासिक जमा से निकाला गया है।</p>
    </section>
    </div>
    <?php $c=ob_get_clean(); layout('My Financial Summary',$c); exit;
}

if($route==='member-dashboard'){
    requireRole(['member']); $m=memberOfUser(); if(!$m){ http_response_code(200); ob_start(); ?><div class="panel"><h2>Member profile link nahi mila</h2><p>आपका login सफल है, लेकिन इस user से Member ID जुड़ी नहीं है। Admin से Member ID mapping जाँच करवाएँ।</p><a class="btn" href="?route=logout">Logout</a></div><?php $c=ob_get_clean(); layout('Member Dashboard',$c); exit; } $deposit=0.0;$limit=0.0;$loan=0.0;$emiOut=0.0;$myInterest=0.0;$myRefund=0.0;$available=0.0;$mid=(int)$m['id'];try{$deposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id={$mid} AND status='Paid'");}catch(Throwable $e){}$limit=$deposit*(float)getSetting('loan_eligibility_percent','80')/100;try{$loan=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans WHERE member_id={$mid} AND status='Active'");}catch(Throwable $e){}try{$emiOut=(float)$db->querySingle("SELECT COALESCE(SUM(MAX(e.amount-e.paid_amount,0)),0) FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE l.member_id={$mid}");}catch(Throwable $e){}$myInterest=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger WHERE member_id={$mid}");try{$myRefund=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE member_id={$mid} AND status='Approved'");}catch(Throwable $e){}$available=($m['status']??'')==='Closed'?0:max(0,round($deposit+$myInterest-$myRefund,2));try { $staffNames=(string)$db->querySingle("SELECT COALESCE(GROUP_CONCAT(COALESCE(NULLIF(u.display_name,''),u.username), ', '),'Not assigned') FROM staff_member_assignments a JOIN users u ON u.id=a.staff_id WHERE a.member_id=".(int)$m['id']); } catch (Throwable $e) { $staffNames='Not assigned'; }$societyDeposits=0.0; try { $societyDeposits=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'"); } catch (Throwable $e) { $societyDeposits=0.0; } $societyLoans=0.0; try { $societyLoans=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans WHERE status='Active'"); } catch (Throwable $e) { $societyLoans=0.0; }$all=null;
    // Member dashboard ticker: society notices + ALL members' recent paid contributions (visible to every member)
    $memberDashFeed=[];
    if(getSetting('notice_enabled','1')==='1'){
        try {
            $nr=$db->query("SELECT title,body,created_at FROM notices WHERE enabled=1 ORDER BY id DESC LIMIT 10");
            while($nr && ($n=$nr->fetchArray(SQLITE3_ASSOC))){
                $tt=trim((string)($n['title']??'')); $bb=trim((string)($n['body']??''));
                if($tt==='' && $bb==='') continue;
                $txt=$tt!=='' ? ('📢 '.$tt.($bb!==''?' — '.$bb:'')) : ('📢 '.$bb);
                $memberDashFeed[]=['time'=>(string)$n['created_at'],'text'=>$txt];
            }
        } catch(Throwable $e) {}
        $staticDashNotice=trim(getSetting('notice_text',''));
        if($staticDashNotice!=='') array_unshift($memberDashFeed,['time'=>date('Y-m-d H:i:s'),'text'=>'📢 '.$staticDashNotice]);
        // Society-wide contribution activity — every member sees when anyone pays
        try {
            $cq=$db->query("SELECT c.amount,c.month,c.created_at,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Paid' ORDER BY c.id DESC LIMIT 15");
            while($cq && ($c=$cq->fetchArray(SQLITE3_ASSOC))){
                $nm=trim((string)($c['name']??'Member'));
                $code=trim((string)($c['code']??''));
                $amt=number_format((float)($c['amount']??0),2);
                $mon=trim((string)($c['month']??''));
                $memberDashFeed[]=['time'=>(string)$c['created_at'],'text'=>'💰 '.$nm.($code!==''?' ('.$code.')':'').' ने ₹'.$amt.' contribution जमा किया'.($mon!==''?' · '.$mon:'')];
            }
        } catch(Throwable $e) {}
        if(!$memberDashFeed){
            $memberDashFeed[]=['time'=>date('Y-m-d H:i:s'),'text'=>'📢 Welcome to GS Suraha. Please keep your member details updated.'];
        }
    }
    usort($memberDashFeed,static fn($a,$b)=>strtotime((string)$b['time'])<=>strtotime((string)$a['time']));
    $memberDashTickerParts=[];
    $seen=[];
    foreach($memberDashFeed as $feedItem){
        $feedText=preg_replace('/\s+/u',' ',trim((string)($feedItem['text']??'')));
        if($feedText==='' || isset($seen[$feedText])) continue;
        $seen[$feedText]=true;
        $memberDashTickerParts[]=$feedText;
    }
    $memberDashTicker=implode('   •   ',$memberDashTickerParts);
    $memberActivityRows=[]; try{$mar=$db->query("SELECT * FROM (SELECT 'Contribution' AS type,amount,status,created_at FROM contributions WHERE member_id={$mid} UNION ALL SELECT 'EMI Payment' AS type,amount,status,created_at FROM payments WHERE member_id={$mid}) ORDER BY created_at DESC LIMIT 5"); while($mar && ($mx=$mar->fetchArray(SQLITE3_ASSOC)))$memberActivityRows[]=$mx;}catch(Throwable $e){$memberActivityRows=[];}
    ob_start();
    $mdSoc=getSetting('society_name','GS Suraha Sahyog Samiti');
    $mdTag=getSetting('society_tagline','Together for a Stronger Tomorrow');
    ?>
<div class="md-app">
  <!-- Member dashboard uses the single global application header above. -->

  <!-- Welcome: photo + name + pill in ONE row -->
  <section class="md-welcome">
    <div class="md-user">
      <?php if(!empty($m['photo'])): ?>
        <img class="md-avatar md-avatar-menu-trigger" src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>" role="button" tabindex="0" aria-label="Open side menu" onclick="toggleMobileMenu()" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleMobileMenu();}">
      <?php else: ?>
        <div class="md-avatar md-avatar-ph md-avatar-menu-trigger" role="button" tabindex="0" aria-label="Open side menu" onclick="toggleMobileMenu()" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleMobileMenu();}">👤</div>
      <?php endif; ?>
      <div class="md-user-info">
        <div class="md-greeting">Namaste</div>
        <h1><span><?=h($m['name'])?></span></h1>
        <p class="md-member-id">Member ID: <?=h($m['code'])?></p>
        <p class="md-desktop-only">Your savings and account activity at a glance</p>
      </div>
    </div>
    <div class="md-pill md-mobile-only">
      <span class="md-pill-icon">👥</span>
      <span class="md-pill-text">Stronger Members<br>Brighter Futures</span>
    </div>
    <div class="md-desktop-tagline md-desktop-only">
      <em>Small Savings<br>Build a Brighter Tomorrow</em>
    </div>
  </section>

  <!-- KPI Cards -->
  <section class="md-kpis">
    <a class="md-kpi" href="?route=member-payment-history">
      <div class="md-kpi-icon md-kpi-green">💰</div>
      <div class="md-kpi-body">
        <span>My Deposit</span>
        <b><?=money($deposit)?></b>
        <small class="md-desktop-only">Your total savings with us</small>
      </div>
      <span class="md-kpi-arrow md-mobile-only">›</span>
    </a>
    <a class="md-kpi" href="?route=member-balances">
      <div class="md-kpi-icon md-kpi-blue">📈</div>
      <div class="md-kpi-body">
        <span>Interest Earned</span>
        <b><?=money($myInterest)?></b>
        <small class="md-desktop-only">Growth on your savings</small>
      </div>
      <span class="md-kpi-arrow md-mobile-only">›</span>
    </a>
    <a class="md-kpi" href="?route=member-loan-apply">
      <div class="md-kpi-icon md-kpi-sky">🤝</div>
      <div class="md-kpi-body">
        <span>Eligible Loan</span>
        <b><?=money($limit)?></b>
        <small class="md-desktop-only">Based on your contribution</small>
      </div>
      <span class="md-kpi-arrow md-mobile-only">›</span>
    </a>
    <a class="md-kpi" href="?route=member-payment-history">
      <div class="md-kpi-icon md-kpi-orange">📄</div>
      <div class="md-kpi-body">
        <span>Outstanding EMI</span>
        <b><?=money($emiOut)?></b>
        <small class="md-desktop-only">Next payment due as per schedule</small>
      </div>
      <span class="md-kpi-arrow md-mobile-only">›</span>
    </a>
  </section>

  <!-- Mobile Quick Actions -->
  <section class="md-quick-card md-mobile-only">
    <div class="md-section-head">
      <div class="md-section-title"><span class="md-bolt">⚡</span><h2>Quick Actions</h2></div>
      <a href="?route=member-profile">All Services ›</a>
    </div>
    <div class="md-quick-grid">
      <a class="md-quick-item" href="?route=member-pay"><div class="md-qicon md-q-green">₹</div><span>Pay<br>Contribution</span></a>
      <a class="md-quick-item" href="?route=member-loan-apply"><div class="md-qicon md-q-blue">📝</div><span>Apply<br>Loan</span></a>
      <a class="md-quick-item" href="?route=member-payment-history"><div class="md-qicon md-q-orange">🔄</div><span>Payment<br>History</span></a>
      <a class="md-quick-item" href="?route=member-profile"><div class="md-qicon md-q-purple">👤</div><span>My<br>Profile</span></a>
    </div>
  </section>

  <!-- Latest Notice — single ticker (mobile + desktop) -->
  <section class="md-notice">
    <div class="md-notice-icon">📢</div>
    <div class="md-notice-content">
      <div class="md-notice-label">सूचना / Notice</div>
      <div class="md-notice-track">
        <div class="md-notice-marquee-run">
          <?php
            $mdTickerText = $memberDashTicker!==''?$memberDashTicker:('Welcome to '.$mdSoc.'. Please keep your member details updated.');
            // Duplicate for seamless loop
            echo '<span>'.h($mdTickerText).'</span><span aria-hidden="true">'.h($mdTickerText).'</span>';
          ?>
        </div>
      </div>
    </div>
    <a class="md-notice-arrow" href="?route=notifications">›</a>
  </section>

  <!-- Mobile Recent Activity -->
  <section class="md-activity md-mobile-only">
    <div class="md-section-head">
      <div class="md-section-title"><span class="md-clock">◷</span><h2>Recent Activity</h2></div>
      <a href="?route=member-payment-history">View All ›</a>
    </div>
    <div class="md-activity-list">
      <?php if($memberActivityRows): foreach($memberActivityRows as $ma):
        $status=strtolower((string)$ma['status']);
        $isPaid = in_array($status,['paid','approved'],true);
        $typeLabel = $ma['type']==='Contribution' ? 'Monthly Contribution' : 'Loan EMI Payment';
        $iconClass = $ma['type']==='Contribution' ? 'md-act-up' : 'md-act-doc';
      ?>
      <div class="md-activity-row">
        <div class="md-act-icon <?=$iconClass?>"><?=$ma['type']==='Contribution'?'↑':'▤'?></div>
        <div class="md-act-info">
          <b><?=h($typeLabel)?></b>
          <small><?=h(date('j M Y, h:i A', strtotime((string)$ma['created_at'])))?></small>
        </div>
        <div class="md-act-right">
          <strong><?=money((float)$ma['amount'])?></strong>
          <span class="md-status <?=$isPaid?'paid':'pending'?>"><?=h(strtoupper((string)$ma['status']))?></span>
        </div>
      </div>
      <?php endforeach; else: ?>
      <div class="md-activity-empty">No recent activity yet.</div>
      <?php endif; ?>
    </div>
  </section>

  <!-- Desktop content grid -->
  <div class="md-content-grid md-desktop-only">
    <section class="md-activity">
      <div class="md-section-head">
        <div class="md-section-title"><span class="md-clock">◷</span><h2>Recent Activity</h2></div>
        <a href="?route=member-payment-history">View All ›</a>
      </div>
      <div class="md-table">
        <div class="md-table-head"><span>Date</span><span>Description</span><span>Amount</span><span>Status</span></div>
        <?php if($memberActivityRows): foreach($memberActivityRows as $ma):
          $status=strtolower((string)$ma['status']);
          $isPaid = in_array($status,['paid','approved'],true);
          $typeLabel = $ma['type']==='Contribution' ? 'Monthly Contribution' : 'Loan EMI Payment';
        ?>
        <div class="md-table-row">
          <span><?=h(date('d M Y', strtotime((string)$ma['created_at'])))?></span>
          <span><?=h($typeLabel)?></span>
          <span><?=money((float)$ma['amount'])?></span>
          <span class="md-status <?=$isPaid?'paid':'pending'?>"><?=$isPaid?'✓ ':''?><?=h(ucfirst((string)$ma['status']))?></span>
        </div>
        <?php endforeach; else: ?>
        <div class="md-activity-empty">No recent activity yet.</div>
        <?php endif; ?>
      </div>
    </section>
    <section class="md-quick-card">
      <div class="md-section-head">
        <div class="md-section-title"><span class="md-bolt">⚡</span><h2>Quick Actions</h2></div>
      </div>
      <div class="md-quick-desktop">
        <a class="md-qd-btn md-qd-green" href="?route=member-pay">💳 Pay Contribution <span>›</span></a>
        <a class="md-qd-btn md-qd-blue" href="?route=member-loan-apply">🤝 Apply for Loan <span>›</span></a>
        <a class="md-qd-btn md-qd-sky" href="?route=member-payment-history">📄 View Payment History <span>›</span></a>
      </div>
    </section>
  </div>
</div>
<?php $c=ob_get_clean(); layout('Member Dashboard',$c); exit;
}

if($route==='member-id-card'){
    requireLogin(); $u=user(); $id=(int)($_GET['id']??0); if($u['role']==='member')$id=(int)$u['member_id'];
    if($u['role']==='member' && $id!==(int)$u['member_id'])exit('Access denied');
    $st=$db->prepare("SELECT * FROM members WHERE id=?");$st->bindValue(1,$id,SQLITE3_INTEGER);$m=$st->execute()->fetchArray(SQLITE3_ASSOC);if(!$m)exit('Member not found');
    $soc=getSetting('society_name','GS Suraha Sahyog Samiti');$tag=getSetting('society_tagline','Finance Co-operative Society');
    $memberVerify = memberVerifyUrl((string)$m['code']);
    $memberQr = 'https://quickchart.io/qr?size=240&margin=2&ecLevel=M&text='.rawurlencode($memberVerify);
    $authorizedSig=getSetting('authorized_signature','');
    $primary=getSetting('idcard_primary','#0b65d5'); $secondary=getSetting('idcard_secondary','#06265b'); $textColor=getSetting('idcard_text','#17324d'); $backText=getSetting('idcard_back_text','#4e6076'); $footer=getSetting('idcard_footer','सहयोग से समृद्धि'); $radius=(int)getSetting('idcard_border_radius','12');
    $showPhoto=getSetting('idcard_show_photo','1')==='1'; $showFather=getSetting('idcard_show_father','1')==='1'; $showMobile=getSetting('idcard_show_mobile','1')==='1'; $showStatus=getSetting('idcard_show_status','1')==='1'; $showAddress=getSetting('idcard_show_address','1')==='1'; $showQr=getSetting('idcard_show_qr','1')==='1'; $showSigs=getSetting('idcard_show_signatures','1')==='1';
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Member ID Card · <?=h($m['code'])?></title><link rel="stylesheet" href="assets/style.css?v=20261104-v175-notice-ticker"><style>
    .id-card-page .id-card{border-radius:<?=$radius?>px;position:relative;background:linear-gradient(135deg,#fffaf3 0%,#ffffff 48%,#f4fbf4 100%)!important}
    .id-card-page .id-card-head,.id-card-page .id-back-head{background:linear-gradient(120deg,#ff9933 0%,#ffd9a8 22%,#ffffff 46%,#dcefdc 70%,#138808 100%)!important;color:#17324d!important}
    .id-card-page .id-back{background:linear-gradient(135deg,#fffaf3 0%,#ffffff 48%,#f4fbf4 100%)!important}
    .id-card-page .id-back-body{background:linear-gradient(135deg,rgba(255,244,228,.82),rgba(255,255,255,.75) 48%,rgba(225,244,229,.86))!important}
    .id-card-page .id-card:before{inset:0!important;background:radial-gradient(90% 68% at 8% 108%,transparent 58%,rgba(255,153,0,.86) 59%,rgba(255,153,0,.86) 61%,transparent 62%),radial-gradient(100% 74% at 92% 108%,transparent 59%,rgba(19,136,8,.82) 60%,rgba(19,136,8,.82) 62%,transparent 63%),radial-gradient(72% 50% at 50% 115%,transparent 64%,rgba(255,255,255,.96) 65%,rgba(255,255,255,.96) 66%,transparent 67%)!important}
    .id-card-page .id-card-foot{position:relative!important;overflow:hidden!important;background:linear-gradient(120deg,#ff9933 0%,#ffd9a8 22%,#ffffff 46%,#dcefdc 70%,#138808 100%)!important;color:#17324d!important;border-top:0!important;text-shadow:0 1px 1px rgba(255,255,255,.55)}
    .id-card-page .id-card-foot:after{content:"";display:block!important;position:absolute!important;inset:0!important;pointer-events:none!important;z-index:0!important;background:radial-gradient(120% 150% at 0% 130%,transparent 62%,rgba(255,153,0,.72) 63%,rgba(255,153,0,.72) 66%,transparent 67%),radial-gradient(120% 150% at 100% 130%,transparent 62%,rgba(19,136,8,.70) 63%,rgba(19,136,8,.70) 66%,transparent 67%),radial-gradient(90% 120% at 50% 135%,transparent 66%,rgba(255,255,255,.92) 67%,rgba(255,255,255,.92) 69%,transparent 70%)!important}
    .id-card-page .id-card-foot>span,.id-card-page .id-card-foot>b{position:relative!important;z-index:1!important;color:#17324d!important}
    .id-card-page .id-card,.id-card-page .id-row b{color:<?=h($textColor)?>}
    .id-card-page .id-back-body p{color:<?=h($backText)?>!important}
    </style></head><body class="id-card-page"><div class="id-card-actions"><button class="btn primary" onclick="window.print()">🖨️ Print / Save PDF</button><a class="btn" href="javascript:history.back()">← Back</a></div><div class="id-card-pair">
    <main class="id-card id-front">
      <div class="id-card-head"><div class="id-brand"><img src="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>" alt="GS Suraha logo"><div><b>GS सुराहा सहयोग समिति</b><small><?=h($tag)?></small></div></div><div class="id-member-head"><div class="id-member-head-text"><span>MEMBER ID / सदस्य आईडी</span><strong><?=h($m['code'])?></strong></div></div></div>
      <div class="id-card-main">
        <?php if($showPhoto): ?><div class="card-photo id-photo"><?php if(!empty($m['photo'])):?><img src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>"><?php else:?><span>👤</span><?php endif;?></div><?php endif; ?>
        <div class="id-details"><div class="id-row"><span>Name / नाम :-</span><b><?=h($m['name'])?></b></div><?php if($showFather): ?><div class="id-row"><span>Father's Name / पिता का नाम :-</span><b><?=h($m['father_name']?:'—')?></b></div><?php endif; ?><?php if($showMobile): ?><div class="id-row"><span>Mobile / मोबाइल :-</span><b><?=h($m['mobile'])?></b></div><?php endif; ?><?php if($showStatus): ?><div class="id-row"><span>Status / स्थिति :-</span><b><?=h($m['status'])?></b></div><?php endif; ?></div>
        <?php if($showQr): ?><div class="id-card-qr"><img class="member-qr-img" src="<?=h($memberQr)?>" alt="Member QR code"><small>SCAN / सत्यापन</small></div><?php endif; ?>
      </div>
      <?php if($showSigs): ?><div class="id-signatures"><div class="sig-box"><span>Member Signature / सदस्य हस्ताक्षर</span><?php if(!empty($m['signature'])):?><img src="<?=signatureFileUrl($m['signature'])?>" alt="Member signature"><?php else:?><b>________________</b><?php endif;?></div><div class="sig-box"><span>Authorized Signatory / अधिकृत हस्ताक्षर</span><?php if($authorizedSig):?><img src="<?=signatureFileUrl($authorizedSig)?>" alt="Authorized signature"><?php else:?><b>________________</b><?php endif;?></div></div><?php endif; ?>
      <div class="id-card-foot"><span><?=h($soc)?></span><b><?=h($footer)?></b></div>
    </main>
    <main class="id-card id-back"><div class="id-back-head">GS सुराहा सहयोग समिति · MEMBER CARD</div><div class="id-back-body"><?php if($showQr): ?><div class="id-qr-box"><img class="member-qr-img member-qr-back" src="<?=h($memberQr)?>" alt="Member QR code"><small>QR / Verify</small></div><?php endif; ?><div><p><b>Important / महत्वपूर्ण</b></p><p>यह कार्ड संस्था की संपत्ति है। खो जाने पर संस्था को सूचित करें।</p><p>This card is issued for official member identification and verification.</p><div class="id-row"><span>Member / सदस्य</span><b><?=h($m['name'])?></b></div><?php if($showFather): ?><div class="id-row"><span>Father's Name / पिता का नाम</span><b><?=h($m['father_name']?:'—')?></b></div><?php endif; ?><?php if($showAddress): ?><div class="id-row"><span>Address / पता</span><b><?=h($m['address']?:'—')?></b></div><?php endif; ?></div></div><?php if($showSigs): ?><div class="id-signatures"><div class="sig-box"><span>Member / सदस्य</span><?php if(!empty($m['signature'])):?><img src="<?=signatureFileUrl($m['signature'])?>" alt="Member signature"><?php else:?><b>________________</b><?php endif;?></div><div class="sig-box"><span>aaa</span><?php if($authorizedSig):?><img src="<?=signatureFileUrl($authorizedSig)?>" alt="Authorized signature"><?php else:?><b>________________</b><?php endif;?></div></div><?php endif; ?><div class="id-card-foot"><span><?=h($soc)?></span><b><?=h($footer)?></b></div></main></div><p class="id-print-note">Modern front + back member ID card · Print both sides / दोनों तरफ प्रिंट करें</p></body></html><?php exit;
}

if($route==='admin-signatures'){
    requireRole(['admin']);
    $memberId=(int)($_GET['member_id']??0); $msg=''; $msgType='success';
    $members=$db->query("SELECT id,code,name FROM members ORDER BY name");
    $selected=null; if($memberId>0){$q=$db->prepare('SELECT * FROM members WHERE id=?');$q->bindValue(1,$memberId,SQLITE3_INTEGER);$selected=$q->execute()->fetchArray(SQLITE3_ASSOC);}
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=$_POST['action']??'';
        try{
            if($action==='authorized_signature'){
                $sig=uploadSignature('authorized_signature','AUTHORIZED','Authorized_Signature'); if($sig==='') throw new RuntimeException('Please select the authorized signature image.');
                $old=getSetting('authorized_signature',''); if($old){$fp=__DIR__.'/'.ltrim($old,'/');if(is_file($fp))@unlink($fp);}
                $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");$st->bindValue(1,'authorized_signature');$st->bindValue(2,$sig);$st->execute();$msg='Authorized signature uploaded successfully.';
            } elseif($action==='member_signature'){
                $mid=(int)($_POST['member_id']??0); $q=$db->prepare('SELECT * FROM members WHERE id=?');$q->bindValue(1,$mid,SQLITE3_INTEGER);$mm=$q->execute()->fetchArray(SQLITE3_ASSOC); if(!$mm) throw new RuntimeException('Member not found.');
                $sig=uploadSignature('member_signature',$mm['code'],'Member_Signature'); if($sig==='') throw new RuntimeException('Please select the member signature image.');
                if(!empty($mm['signature'])){$fp=__DIR__.'/'.ltrim($mm['signature'],'/');if(is_file($fp))@unlink($fp);}
                $up=$db->prepare('UPDATE members SET signature=? WHERE id=?');$up->bindValue(1,$sig);$up->bindValue(2,$mid,SQLITE3_INTEGER);$up->execute();$selected=$mm;$selected['signature']=$sig;$memberId=$mid;$msg='Member signature uploaded successfully.';
            }
        }catch(Throwable $e){$msg=$e->getMessage();$msgType='danger';}
    }
    $authorized=getSetting('authorized_signature','');
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ADMIN CONTROL</div><h1>Signature Uploads / हस्ताक्षर</h1><p>Upload the two signatures used on Member ID cards. <span class="hi-sub">ID Card के लिए सदस्य और अधिकृत हस्ताक्षर अपलोड करें।</span></p></div><a class="btn" href="?route=members">← Members</a></div><?php if($msg):?><div class="alert <?=$msgType==='danger'?'danger':'success'?>"><?=h($msg)?></div><?php endif;?><div class="grid-2"><div class="panel"><div class="panel-head"><h2>1. Authorized Signature / अधिकृत हस्ताक्षर</h2><span class="badge success">Admin Only</span></div><?php if($authorized):?><div class="signature-preview"><img src="<?=signatureFileUrl($authorized)?>" alt="Authorized signature"></div><?php endif;?><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="authorized_signature"><label>Authorized Signature Image <small>(PNG/JPG/WebP, max 2MB)</small></label><input type="file" name="authorized_signature" accept="image/jpeg,image/png,image/webp" required><button class="btn primary full">✍ Upload Authorized Signature</button></form></div><div class="panel"><div class="panel-head"><h2>2. Member Signature / सदस्य हस्ताक्षर</h2><span class="badge">Per Member</span></div><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="member_signature"><label>Select Member</label><select name="member_id" required onchange="location.href='?route=admin-signatures&member_id='+this.value"><option value="">Select member</option><?php while($mm=$members->fetchArray(SQLITE3_ASSOC)):?><option value="<?=$mm['id']?>" <?=$memberId===(int)$mm['id']?'selected':''?>><?=h($mm['code'].' · '.$mm['name'])?></option><?php endwhile;?></select><?php if($selected):?><div class="selected-member-sign"><b><?=h($selected['name'])?></b><small><?=h($selected['code'])?></small><?php if(!empty($selected['signature'])):?><img src="<?=signatureFileUrl($selected['signature'])?>" alt="Member signature"><?php endif;?></div><label>Member Signature Image <small>(PNG/JPG/WebP, max 2MB)</small></label><input type="file" name="member_signature" accept="image/jpeg,image/png,image/webp" required><button class="btn primary full">✍ Upload Member Signature</button><?php else:?><div class="alert info">Select a member to upload their signature.</div><?php endif;?></form></div></div><?php $c=ob_get_clean(); layout('Signature Uploads',$c); exit;
}

if($route==='account-settings'){
    requireRole(['staff','member']);
    $u=user(); $msg=''; $msgType='success';
    $m=$u['role']==='member' ? memberOfUser() : null;
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        try {
            // Member mobile is locked. Only Admin may change the registered mobile number.
            if($u['role']==='member') throw new Exception('Mobile number is locked. Please contact Admin to change it. / मोबाइल नंबर लॉक है। बदलने के लिए Admin से संपर्क करें।');
            throw new Exception('Account changes are managed by Admin.');
        } catch(Throwable $e){ $msg=$e->getMessage(); $msgType='danger'; }
    }
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">MY ACCOUNT</div><h1>Account Settings</h1><p><?= $m ? 'Your registered mobile number is locked. Only Admin can change it. <span class="hi-sub">आपका रजिस्टर्ड मोबाइल नंबर लॉक है। केवल Admin इसे बदल सकता है।</span>' : 'Your login account is managed by Admin. <span class="hi-sub">आपका लॉगिन अकाउंट एडमिन द्वारा प्रबंधित है।</span>' ?></p></div></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-2">
      <div class="panel"><div class="member-photo-wrap"><div class="member-photo placeholder">👤</div><div><h2><?=h($m['name'] ?? (($u['display_name'] ?? '') ?: $u['username']))?></h2><p class="muted"><?=h(ucfirst($u['role']))?></p></div></div>
      <div class="profile-grid"><div><b>Login ID</b><span><?=h($u['username'])?></span></div><?php if($m): ?><div><b>Current Mobile</b><span><?=h($m['mobile'])?></span></div><?php endif; ?><div><b>Role</b><span><?=h(ucfirst($u['role']))?></span></div><div><b>Last Login</b><span><?=h($_SESSION['login_time'] ?? 'Current session')?></span></div></div></div>
      <div class="panel"><h2><?= $m ? 'Mobile Number Locked / मोबाइल लॉक' : 'Account Access' ?></h2>
         <?php if($m): ?><div class="alert success">🔒 <b>Mobile number is locked.</b><br>Current Mobile / वर्तमान मोबाइल: <b><?=h($m['mobile'])?></b><br><span class="hi-sub">सदस्य अब अपना मोबाइल नंबर बदल नहीं सकता। बदलाव केवल Admin कर सकता है।</span></div><div class="alert info" style="margin-top:12px">To change this number, please contact Admin. / नंबर बदलने के लिए Admin से संपर्क करें।</div><?php else: ?><div class="alert info">Staff login ID, name and password are controlled by Admin. Please contact Admin for any account change.</div><?php endif; ?>
       </div>
    </div>
    <?php $c=ob_get_clean(); layout('Account Settings',$c); exit;
}

if($route==='upload-payment-slip-pdf'){
    requireRole(['admin','staff']);
    header('Content-Type: application/json; charset=utf-8');
    $csrfPost=(string)($_POST['csrf']??'');
    if($csrfPost==='' || !hash_equals((string)csrf(),$csrfPost)){ echo json_encode(['ok'=>false,'message'=>'Invalid security token.']); exit; }
    $type=strtolower(trim((string)($_POST['type']??'')));
    $id=(int)($_POST['id']??0);
    if(!in_array($type,['emi','contribution'],true) || $id<=0){ echo json_encode(['ok'=>false,'message'=>'Invalid payment slip.']); exit; }
    if(user()['role']==='admin' && getSetting('payment_send_slip_admin','1')!=='1'){ echo json_encode(['ok'=>false,'message'=>'Admin Send Slip is disabled in Payment System settings.']); exit; }
    if(user()['role']==='staff' && getSetting('payment_send_slip_staff','1')!=='1'){ echo json_encode(['ok'=>false,'message'=>'Staff Send Slip is disabled in Payment System settings.']); exit; }
    if(getSetting('payment_slip_enabled','1')!=='1'){ echo json_encode(['ok'=>false,'message'=>'Payment Slip is disabled in Payment System settings.']); exit; }
    if(empty($_FILES['pdf']) || !isset($_FILES['pdf']['tmp_name']) || (int)$_FILES['pdf']['error']!==UPLOAD_ERR_OK){ echo json_encode(['ok'=>false,'message'=>'PDF upload failed.']); exit; }
    $tmp=(string)$_FILES['pdf']['tmp_name']; $size=(int)$_FILES['pdf']['size'];
    if($size<=0 || $size>10*1024*1024){ echo json_encode(['ok'=>false,'message'=>'PDF must be between 1 byte and 10 MB.']); exit; }
    $head=(string)file_get_contents($tmp, false, null, 0, 5);
    if($head!=='%PDF-'){ echo json_encode(['ok'=>false,'message'=>'Uploaded file is not a valid PDF.']); exit; }
    if($type==='emi'){
        $st=$db->prepare("SELECT p.*,m.name AS member_name,m.code AS member_code,m.mobile,e.installment_no FROM payments p JOIN members m ON m.id=p.member_id LEFT JOIN emi_schedule e ON e.id=p.emi_id WHERE p.id=? AND p.status='Paid'");
    } else {
        $st=$db->prepare("SELECT p.*,m.name AS member_name,m.code AS member_code,m.mobile FROM contributions p JOIN members m ON m.id=p.member_id WHERE p.id=? AND p.status='Paid'");
    }
    $st->bindValue(1,$id,SQLITE3_INTEGER); $row=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$row){ echo json_encode(['ok'=>false,'message'=>'Paid payment slip not found.']); exit; }
    $dir=__DIR__.'/uploads/payment-slips'; if(!is_dir($dir) && !mkdir($dir,0775,true) && !is_dir($dir)){ echo json_encode(['ok'=>false,'message'=>'Unable to create PDF folder.']); exit; }
    $filename='site-payment-slip-'.$type.'-'.$id.'-'.bin2hex(random_bytes(6)).'.pdf';
    $dest=$dir.'/'.$filename;
    if(!move_uploaded_file($tmp,$dest)){ echo json_encode(['ok'=>false,'message'=>'Unable to save generated PDF on server.']); exit; }
    $rel='uploads/payment-slips/'.$filename;
    [$ok,$msg,$sentPdfRel]=sendWhatsAppPaymentSlip((string)$row['mobile'],(string)$row['member_name'],(float)$row['amount'],$type,$id,(string)($row['member_code']??''),(string)($row['txn_id']??''),(string)($row['created_at']??date('Y-m-d H:i:s')),$rel);
    echo json_encode(['ok'=>$ok,'message'=>$msg,'pdf'=>$sentPdfRel?:$rel],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit;
}

if($route==='send-payment-slip'){
    requireRole(['admin','staff']);
    $type=strtolower(trim((string)($_GET['type']??'')));
    $id=(int)($_GET['id']??0);
    if(!in_array($type,['emi','contribution'],true) || $id<=0) exit('Invalid payment slip.');
    if(user()['role']==='admin' && getSetting('payment_send_slip_admin','1')!=='1') exit('Admin Send Slip is disabled in Payment System settings.');
    if(user()['role']==='staff' && getSetting('payment_send_slip_staff','1')!=='1') exit('Staff Send Slip is disabled in Payment System settings.');
    if(getSetting('payment_slip_enabled','1')!=='1') exit('Payment Slip is disabled in Payment System settings.');
    if($type==='emi'){
        $st=$db->prepare("SELECT p.*, e.installment_no, e.due_date, m.name AS member_name, m.code AS member_code, m.mobile AS member_mobile FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id JOIN members m ON m.id=p.member_id WHERE p.id=? AND p.status='Paid'");
    } else {
        $st=$db->prepare("SELECT c.*, m.name AS member_name, m.code AS member_code, m.mobile AS member_mobile FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.id=? AND c.status='Paid'");
    }
    $st->bindValue(1,$id,SQLITE3_INTEGER); $row=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$row) exit('Paid payment slip not found.');
    $society=getSetting('society_name','GS Suraha Sahyog Samiti');
    $tagline=getSetting('society_tagline','Finance Co-operative Society');
    $label=$type==='emi'?'EMI Payment':'Contribution Payment';
    $sub=$type==='emi' ? ('EMI #'.(string)($row['installment_no']??'').' · Due '.(string)($row['due_date']??'')) : ('Month: '.(string)($row['month']??''));
    $m=['name'=>$row['member_name'],'code'=>$row['member_code'],'mobile'=>$row['member_mobile']??''];
    ob_start(); ?>
    <div class="receipt-page send-slip-preview-page">
      <div class="receipt-actions no-print modern-receipt-actions"><button class="btn primary" type="button" id="sendExactSlip">📤 Send Exact Site Slip PDF</button><a class="btn" href="?route=<?=h($type==='emi'?'emi-payments':'contributions')?>">← Back</a></div>
      <div id="exactSlip" class="payment-receipt" style="--slip-primary:<?=h(getSetting('slip_primary','#0b65d5'))?>;--slip-secondary:<?=h(getSetting('slip_secondary','#06265b'))?>;--slip-text:<?=h(getSetting('slip_text','#17324d'))?>;--slip-radius:<?=h(getSetting('slip_border_radius','12'))?>px;color:var(--slip-text);border-radius:var(--slip-radius);">
        <div class="receipt-head receipt-screenshot-head">
          <?php if(getSetting("slip_show_logo","1")==="1"): ?><img src="<?=h(getSetting("header_logo","assets/logo.png"))?>" alt="GS Suraha" class="receipt-logo"><?php endif; ?>
          <div><div class="receipt-eyebrow">PAYMENT RECEIPT / भुगतान रसीद</div><h1><?=h($society)?></h1><p><?=h($tagline)?></p></div>
        </div>
        <?php if(getSetting("slip_show_status","1")==="1"): ?><div class="receipt-status">✓ PAYMENT VERIFIED · भुगतान सत्यापित</div><?php endif; ?>
        <div class="receipt-title"><h2><?=h(getSetting("slip_title_en","PAYMENT RECEIPT"))?></h2><span><?=h(getSetting("slip_title_hi","भुगतान रसीद"))?></span><br><small><?=h($label)?></small><span><?=h($sub)?></span></div>
        <div class="receipt-grid">
          <?php if(getSetting("slip_show_member","1")==="1"): ?><div><small>Member Name / सदस्य का नाम</small><b><?=h($m['name'])?></b></div><div><small>Member ID / सदस्य आईडी</small><b><?=h($m['code'])?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_mobile","1")==="1"): ?><div><small>Mobile / मोबाइल</small><b><?=h($m['mobile'])?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_date","1")==="1"): ?><div><small>Date & Time / दिनांक व समय</small><b><?=h($row['created_at'])?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_mode","1")==="1"): ?><div><small>Payment Mode / भुगतान माध्यम</small><b><?=h($row['mode']??($type==='emi'?'Online UPI':'Contribution'))?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_reference","1")==="1"): ?><div><small>Reference No. / संदर्भ संख्या</small><b><?=h($row['txn_id']??'')?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_status","1")==="1"): ?><div><small>Status / स्थिति</small><b>Paid / भुगतान हुआ</b></div><?php endif; ?>
        </div>
        <div class="receipt-amount"><span>Amount Paid / भुगतान राशि</span><strong><?=money((float)$row['amount'])?></strong></div>
        <?php if(getSetting("slip_show_note","1")==="1"): ?><div class="receipt-note">यह कंप्यूटर द्वारा बनाई गई भुगतान रसीद है। कृपया इसे सुरक्षित रखें।<br>This is a computer-generated payment receipt. Please keep it for your records.</div><?php endif; ?>
        <div class="receipt-foot" style="background:<?=h(getSetting("slip_secondary","#06265b"))?>;color:#fff"><?=h(getSetting("slip_footer","धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।"))?></div>
      </div>
      <div id="sendSlipStatus" class="alert info" style="margin-top:14px">रसीद तैयार हो रही है… कृपया कुछ क्षण प्रतीक्षा करें।</div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script>
    (function(){
      const btn=document.getElementById('sendExactSlip'), box=document.getElementById('exactSlip'), out=document.getElementById('sendSlipStatus');
      const csrf=<?=json_encode(csrf())?>, type=<?=json_encode($type)?>, id=<?=json_encode($id)?>;
      function status(t,ok){out.className='alert '+(ok?'success':'danger');out.textContent=t;}
      async function send(){
        btn.disabled=true; status('रसीद की वही site वाली design PDF में तैयार हो रही है…',true);
        try{
          if(typeof html2canvas==='undefined' || !window.jspdf || !window.jspdf.jsPDF) throw new Error('PDF library load नहीं हुई। Internet/CDN connection check करें।');
          const canvas=await html2canvas(box,{scale:2,useCORS:true,backgroundColor:'#ffffff',logging:false});
          const {jsPDF}=window.jspdf;
          const pdf=new jsPDF({orientation:'portrait',unit:'mm',format:'a4',compress:true});
          const margin=10, pageW=210, pageH=297;
          const imgW=pageW-margin*2, imgH=canvas.height*imgW/canvas.width;
          const y=imgH>pageH-margin*2 ? margin : (pageH-imgH)/2;
          pdf.addImage(canvas.toDataURL('image/jpeg',0.96),'JPEG',margin,y,imgW,Math.min(imgH,pageH-margin*2));
          const blob=pdf.output('blob');
          status('PDF server पर सुरक्षित करके WhatsApp पर भेजा जा रहा है…',true);
          const fd=new FormData(); fd.append('csrf',csrf); fd.append('type',type); fd.append('id',id); fd.append('pdf',blob,'GS-Suraha-Payment-Slip-'+id+'.pdf');
          const res=await fetch('?route=upload-payment-slip-pdf',{method:'POST',body:fd,credentials:'same-origin'});
          const data=await res.json();
          if(!data.ok) throw new Error(data.message||'PDF send failed.');
          status('✅ वही site वाली PDF slip Hindi message के साथ WhatsApp पर भेज दी गई।',true);
          if(data.pdf){ const a=document.createElement('a'); a.href=data.pdf; a.target='_blank'; a.className='btn small'; a.textContent='📄 PDF खोलें'; out.appendChild(document.createTextNode(' ')); out.appendChild(a); }
        }catch(e){ console.error(e); status('❌ '+e.message,false); btn.disabled=false; }
      }
      btn.addEventListener('click',send); window.addEventListener('load',function(){setTimeout(send,500);});
    })();
    </script>
    <?php $c=ob_get_clean(); layout('Send Payment Slip',$c); exit;
}

if($route==='payment-receipt'){
    requireRole(['admin','staff','member']);
    $u=user(); $m=$u['role']==='member' ? memberOfUser() : null; $mid=$m ? (int)$m['id'] : 0;
    $type=strtolower(trim((string)($_GET['type']??'')));
    $id=(int)($_GET['id']??0);
    $r=null; $label=''; $sub='';
    if($type==='emi'){
        if($u['role']==='member'){
            $st=$db->prepare("SELECT p.*, e.installment_no, e.due_date, m.name AS member_name, m.code AS member_code FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id JOIN members m ON m.id=p.member_id WHERE p.id=? AND p.member_id=? AND p.status='Paid'");
            $st->bindValue(1,$id,SQLITE3_INTEGER); $st->bindValue(2,$mid,SQLITE3_INTEGER);
        } else {
            $st=$db->prepare("SELECT p.*, e.installment_no, e.due_date, m.name AS member_name, m.code AS member_code, m.mobile AS member_mobile FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id JOIN members m ON m.id=p.member_id WHERE p.id=? AND p.status='Paid'");
            $st->bindValue(1,$id,SQLITE3_INTEGER);
        }
        $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
        if($r && !$m){ $m=['name'=>$r['member_name'],'code'=>$r['member_code'],'mobile'=>$r['member_mobile']??'']; }
        $label='EMI Payment'; $sub=$r ? ('EMI #'.(string)($r['installment_no']??'').' · Due '.(string)($r['due_date']??'')) : '';
    } else {
        if($u['role']==='member'){
            $st=$db->prepare("SELECT c.*, m.name AS member_name, m.code AS member_code FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.id=? AND c.member_id=? AND c.status='Paid'");
            $st->bindValue(1,$id,SQLITE3_INTEGER); $st->bindValue(2,$mid,SQLITE3_INTEGER);
        } else {
            $st=$db->prepare("SELECT c.*, m.name AS member_name, m.code AS member_code, m.mobile AS member_mobile FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.id=? AND c.status='Paid'");
            $st->bindValue(1,$id,SQLITE3_INTEGER);
        }
        $r=$st->execute()->fetchArray(SQLITE3_ASSOC);
        if($r && !$m){ $m=['name'=>$r['member_name'],'code'=>$r['member_code'],'mobile'=>$r['member_mobile']??'']; }
        $label='Contribution Payment'; $sub=$r ? ('Month: '.(string)$r['month']) : '';
    }
    if(!$r){http_response_code(404);exit('Payment slip not found or payment is not verified yet.');}
    $society=getSetting('society_name','GS Suraha Sahyog Samiti');
    $tagline=getSetting('society_tagline','Finance Co-operative Society');
    ob_start(); ?>
    <div class="receipt-page">
      <div class="receipt-actions no-print modern-receipt-actions"><button class="btn primary" onclick="window.print()">🖨️ Print / Save PDF</button><a class="btn" href="?route=member-payment-history">← Payment History</a></div>
      <div class="payment-receipt" style="--slip-primary:<?=h(getSetting('slip_primary','#0b65d5'))?>;--slip-secondary:<?=h(getSetting('slip_secondary','#06265b'))?>;--slip-text:<?=h(getSetting('slip_text','#17324d'))?>;--slip-radius:<?=h(getSetting('slip_border_radius','12'))?>px;color:var(--slip-text);border-radius:var(--slip-radius);">
        <div class="receipt-head receipt-screenshot-head">
          <?php if(getSetting("slip_show_logo","1")==="1"): ?><img src="<?=h(getSetting("header_logo","assets/logo.png"))?>" alt="GS Suraha" class="receipt-logo"><?php endif; ?>
          <div><div class="receipt-eyebrow">PAYMENT RECEIPT / भुगतान रसीद</div><h1><?=h($society)?></h1><p><?=h($tagline)?></p></div>
        </div>
        <?php if(getSetting("slip_show_status","1")==="1"): ?><div class="receipt-status">✓ PAYMENT VERIFIED · भुगतान सत्यापित</div><?php endif; ?>
        <div class="receipt-title"><h2><?=h(getSetting("slip_title_en","PAYMENT RECEIPT"))?></h2><span><?=h(getSetting("slip_title_hi","भुगतान रसीद"))?></span><br><small><?=h($label)?></small><span><?=h($sub)?></span></div>
        <div class="receipt-grid">
          <?php if(getSetting("slip_show_member","1")==="1"): ?><div><small>Member Name</small><b><?=h($m['name'])?></b></div><div><small>Member ID</small><b><?=h($m['code'])?></b></div><?php endif; ?>
          <?php if(getSetting("slip_show_date","1")==="1"): ?><div><small>Date & Time</small><b><?=h($r['created_at'])?></b></div><?php endif; ?><?php if(getSetting("slip_show_mode","1")==="1"): ?><div><small>Payment Mode</small><b><?=h($r['mode'])?></b></div><?php endif; ?><?php if(getSetting("slip_show_reference","1")==="1"): ?><div><small>Reference No.</small><b><?=h($r['txn_id'])?></b></div><?php endif; ?><?php if(getSetting("slip_show_status","1")==="1"): ?><div><small>Status</small><b>Paid</b></div><?php endif; ?>
        </div>
        <div class="receipt-amount"><span>Amount Paid / भुगतान राशि</span><strong><?=money((float)$r['amount'])?></strong></div>
        <?php if(getSetting("slip_show_note","1")==="1"): ?><div class="receipt-note"><?=nl2br(h(getSetting("slip_footer","धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।")) )?><br>This is a computer-generated payment receipt.</div><?php endif; ?>
        <div class="receipt-foot" style="background:<?=h(getSetting("slip_secondary","#06265b"))?>;color:#fff"><?=h(getSetting("slip_footer","धन्यवाद। कृपया इस रसीद को सुरक्षित रखें।"))?></div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Payment Receipt',$c); exit;
}

if($route==='member-payment-history'){
    requireRole(['member']); $m=memberOfUser(); $mid=(int)$m['id'];
    $con=$db->query("SELECT c.id,c.created_at,c.month,c.amount,c.mode,c.status,c.txn_id,c.reject_reason,'Contribution' AS type FROM contributions c WHERE c.member_id=$mid");
    $emiPay=$db->query("SELECT p.id,p.created_at,'' AS month,p.amount,p.mode,p.status,p.txn_id,p.reject_reason,'EMI' AS type,e.installment_no FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id WHERE p.member_id=$mid");
    $history=[]; while($r=$con->fetchArray(SQLITE3_ASSOC)){$history[]=$r;} while($r=$emiPay->fetchArray(SQLITE3_ASSOC)){$history[]=$r;}
    usort($history,fn($a,$b)=>strcmp((string)$b['created_at'],(string)$a['created_at']));
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ACCOUNT ACTIVITY</div><h1>Payment History</h1><p>All contribution and EMI payment records. <span class="hi-sub">सभी जमा और ईएमआई भुगतान का विवरण।</span></p></div><a class="btn" href="?route=member-dashboard">← Dashboard</a></div><div class="panel payment-history-panel"><div class="table-wrap payment-history-table"><table><thead><tr><th>Date</th><th>Type</th><th>Month / EMI</th><th>Amount</th><th>Mode</th><th>Status</th><th>Reference</th></tr></thead><tbody><?php if(!$history): ?><tr><td colspan="7"><div class="alert info">No payment history found.</div></td></tr><?php else: foreach($history as $r): ?><tr><td><?=h($r['created_at'])?></td><td><b><?=h($r['type'])?></b></td><td><?=h($r['type']==='EMI' ? ('EMI #'.($r['installment_no']??'')) : ($r['month']??''))?></td><td><?=money((float)$r['amount'])?></td><td><?=h($r['mode'])?></td><td><span class="badge <?=strtolower($r['status'])==='paid'?'success':(strtolower($r['status'])==='rejected'?'danger':'warning')?>"><?=h($r['status'])?></span></td><td><?=h($r['txn_id'])?><?php if(strtolower((string)$r['status'])==='paid'): ?><a class="receipt-link" href="?route=payment-receipt&type=<?=strtolower($r['type'])==='emi'?'emi':'contribution'?>&id=<?=isset($r['id'])?(int)$r['id']:0?>" target="_blank" rel="noopener">🧾 Slip</a><?php endif; ?></td></tr><?php endforeach; endif; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('Payment History',$c); exit;
}

if($route==='member-profile'){
    requireRole(['member']); $m=memberOfUser();$deposit=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE member_id=".$m['id']." AND status='Paid'");$p=$db->query("SELECT * FROM contributions WHERE member_id=".$m['id']." ORDER BY id DESC LIMIT 15");$msg='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $newFiles=[];
        try {
            $db->exec('BEGIN IMMEDIATE');
            $freshSt=$db->prepare('SELECT * FROM members WHERE id=?');$freshSt->bindValue(1,(int)$m['id'],SQLITE3_INTEGER);$fresh=$freshSt->execute()->fetchArray(SQLITE3_ASSOC);if(!$fresh)throw new RuntimeException('Member profile not found.');$m=$fresh;
            $photoAttempt=isset($_FILES['photo']) && ($_FILES['photo']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE;
            $signatureAttempt=isset($_FILES['signature']) && ($_FILES['signature']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE;
            // After Admin/Staff unlock (photo_locked=0 / signature_locked=0), member can replace
            if($photoAttempt && !empty($m['photo_locked'])) throw new RuntimeException('Photo locked है। Admin/Staff unlock करें, तब member update कर सकेगा।');
            if($signatureAttempt && !empty($m['signature_locked'])) throw new RuntimeException('Signature locked है। Admin/Staff unlock करें, तब member update कर सकेगा।');
            $photo=$photoAttempt?uploadMemberFile('photo',$m['code'],'Photo'):'';
            if($photo!=='') $newFiles[]=$photo;
            $signature=$signatureAttempt?uploadMemberFile('signature',$m['code'],'Signature'):'';
            if($signature!=='') $newFiles[]=$signature;
            $document=uploadMemberFile('document',$m['code'],'Document');
            if($document!=='') $newFiles[]=$document;
            $sets=[];$values=[];
            if($photo!==''){$sets[]='photo=?';$values[]=$photo;$sets[]='photo_locked=1';}
            if($signature!==''){$sets[]='signature=?';$values[]=$signature;$sets[]='signature_locked=1';}
            if($document!==''){$sets[]='document=?';$values[]=$document;}
            if($sets){
                $where='id=?';
                if($photo!=='') $where.=' AND COALESCE(photo_locked,0)=0';
                if($signature!=='') $where.=' AND COALESCE(signature_locked,0)=0';
                $values[]=(int)$m['id'];
                $st=$db->prepare('UPDATE members SET '.implode(',',$sets).' WHERE '.$where);
                foreach($values as $i=>$v)$st->bindValue($i+1,$v,is_int($v)?SQLITE3_INTEGER:SQLITE3_TEXT);
                if(!$st->execute()||$db->changes()!==1) throw new RuntimeException('Upload failed — photo/signature still locked. Unlock के बाद फिर try करें।');
                // remove previous files after successful replace
                if($photo!=='' && !empty($m['photo'])){ $old=__DIR__.'/'.ltrim((string)$m['photo'],'/'); if(is_file($old)) @unlink($old); }
                if($signature!=='' && !empty($m['signature'])){ $old=__DIR__.'/'.ltrim((string)$m['signature'],'/'); if(is_file($old)) @unlink($old); }
                $db->exec('COMMIT');
                $m=memberOfUser();
                $msg='Upload saved. Photo/Signature ab lock है। दुबारा बदलने के लिए Admin/Staff unlock करें।';
            }
            else {$db->exec('ROLLBACK');$msg='Choose a photo, signature, or document to upload.';}
        } catch(Throwable $e){try{$db->exec('ROLLBACK');}catch(Throwable $ignored){}foreach($newFiles as $file){$path=__DIR__.'/'.ltrim($file,'/');if(is_file($path))@unlink($path);}$msg=$e->getMessage();}
    }
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">MY ACCOUNT</div><h1>My Profile</h1><p><?=h($m['code'])?></p></div><div class="inline-form profile-actions"><a class="btn primary" href="?route=member-id-card">🪪 My ID Card</a><a class="btn danger" href="?route=member-close-request">🔒 Close ID / Refund</a></div></div><?php if($msg): ?><div class="alert info"><?=h($msg)?></div><?php endif; ?><div class="grid-2"><div class="panel"><div class="member-photo-wrap"><?php if(!empty($m['photo'])): ?><img class="member-photo" src="<?=memberFileUrl($m['photo'])?>" alt="<?=h($m['name'])?>"><?php else: ?><div class="member-photo placeholder">👤</div><?php endif; ?><div><h2><?=h($m['name'])?></h2><p class="muted"><?=h($m['mobile'])?></p></div></div><div class="profile-grid"><div><b>Email</b><span><?=h($m['email'])?></span></div><div><b>Address</b><span><?=h($m['address'])?></span></div><div><b>Total Paid</b><span><?=money($deposit)?></span></div></div></div><div class="panel"><h2>Photo, Signature & Document / फोटो, हस्ताक्षर और दस्तावेज़</h2><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><div class="grid-2"><?php if(!empty($m['photo_locked'])): ?><div class="alert success">✓ Photo locked. Admin/Staff unlock करें तो update कर सकेंगे।</div><?php else: ?><label>Profile Photo (JPG/PNG/WebP, max 5MB)<?=!empty($m['photo'])?' <small class="muted">— unlocked, replace allowed</small>':''?><input name="photo" type="file" accept="image/jpeg,image/png,image/webp"></label><?php endif; ?><?php if(!empty($m['signature_locked'])): ?><div class="alert success">✓ Signature locked. Admin/Staff unlock करें तो update कर सकेंगे।</div><?php else: ?><label>Signature (JPG/PNG/WebP, max 5MB)<?=!empty($m['signature'])?' <small class="muted">— unlocked, replace allowed</small>':''?><input name="signature" type="file" accept="image/jpeg,image/png,image/webp"></label><?php endif; ?><label>Document / दस्तावेज़<input name="document" type="file" accept="application/pdf,image/jpeg,image/png,image/webp"></label></div><button class="btn primary full" type="submit">Upload selected files / चयनित फाइलें अपलोड करें</button></form><div class="document-list" style="margin-top:12px"><?php if(!empty($m['photo'])): ?><a class="document-card" href="<?=memberFileUrl($m['photo'])?>" target="_blank" rel="noopener">🖼️ <span>View Photo</span></a><?php endif; ?><?php if(!empty($m['signature'])): ?><a class="document-card" href="<?=memberFileUrl($m['signature'])?>" target="_blank" rel="noopener">✍️ <span>View Signature</span></a><?php endif; ?><?php if(!empty($m['document'])): ?><a class="document-card" href="<?=memberFileUrl($m['document'])?>" target="_blank" rel="noopener">📄 <span>View Document</span></a><?php endif; ?></div></div></div><div class="panel"><h2>Payment History</h2><div class="table-wrap"><table><thead><tr><th>Date</th><th>Month</th><th>Amount</th><th>Mode</th><th>Status</th><th>Reference</th></tr></thead><tbody><?php while($r=$p->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h($r['created_at'])?></td><td><?=h($r['month'])?></td><td><?=money((float)$r['amount'])?></td><td><?=h($r['mode'])?></td><td><?=h($r['status'])?></td><td><?=h($r['txn_id'])?></td></tr><?php endwhile; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('My Profile',$c); exit;
}

if($route==='emi-payments'){
    requireRole(['admin','staff']); $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){checkCsrf();$pid=(int)($_POST['id']??0);$action=$_POST['action']??'';$p=$db->query("SELECT * FROM payments WHERE id=$pid AND status='Pending'")->fetchArray(SQLITE3_ASSOC);if(!$p){$msg='Payment already processed or not found.';$msgType='warning';}elseif($action==='approve'){ $db->exec('BEGIN IMMEDIATE'); try{if(!empty($p['emi_id'])){$cap=$db->prepare("SELECT MAX(0,e.amount-e.paid_amount-COALESCE((SELECT SUM(p2.amount) FROM payments p2 WHERE p2.emi_id=e.id AND p2.status='Pending' AND p2.id<>?),0)) remaining FROM emi_schedule e WHERE e.id=?");$cap->bindValue(1,$pid,SQLITE3_INTEGER);$cap->bindValue(2,(int)$p['emi_id'],SQLITE3_INTEGER);$remaining=(float)($cap->execute()->fetchArray(SQLITE3_ASSOC)['remaining']??-1);if($remaining<0||(float)$p['amount']>$remaining+0.01)throw new RuntimeException('EMI amount exceeds remaining scheduled balance');}$st=$db->prepare("UPDATE payments SET status='Paid' WHERE id=? AND status='Pending'");$st->bindValue(1,$pid);if(!$st->execute()||$db->changes()!==1)throw new Exception();if(!empty($p['emi_id'])){recordVerifiedEmiInterest($p);$st=$db->prepare("UPDATE emi_schedule SET paid_amount=MIN(amount,paid_amount+?),status=CASE WHEN paid_amount+? >= amount THEN 'Paid' ELSE 'Pending' END WHERE id=?");$st->bindValue(1,(float)$p['amount']);$st->bindValue(2,(float)$p['amount']);$st->bindValue(3,(int)$p['emi_id']);if(!$st->execute()||$db->changes()!==1)throw new RuntimeException('EMI schedule update failed');$loanId=(int)($p['loan_id']??0);if($loanId>0){$close=$db->prepare("UPDATE loans SET status='Closed' WHERE id=? AND EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id) AND NOT EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id AND MAX(e.amount-e.paid_amount,0)>0.009)");$close->bindValue(1,$loanId,SQLITE3_INTEGER);if(!$close->execute())throw new RuntimeException('Loan closure update failed');}}$db->exec('COMMIT');$msg='EMI payment verified and EMI updated.'; if(getSetting('whatsapp_auto_emi_paid_enabled','0')==='1'){ $mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$p['member_id'])->fetchArray(SQLITE3_ASSOC); if($mm){$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'emi_paid',['amount'=>number_format((float)$p['amount'],2),'txn'=>(string)$p['txn_id']])); if(!$wr[0]){$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1];}} }}catch(Throwable $e){$db->exec('ROLLBACK');$msg='Verification failed.';$msgType='danger';}}elseif($action==='reject'){ $reason=trim((string)($_POST['reject_reason']??'')); if($reason===''){ $msg='Reject reason is required.'; $msgType='danger'; } else { $st=$db->prepare("UPDATE payments SET status='Rejected',reject_reason=?,rejected_by=?,rejected_at=CURRENT_TIMESTAMP WHERE id=? AND status='Pending'");$st->bindValue(1,$reason,SQLITE3_TEXT);$st->bindValue(2,(int)user()['id'],SQLITE3_INTEGER);$st->bindValue(3,$pid,SQLITE3_INTEGER); if($st->execute() && $db->changes()===1){$mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$p['member_id'])->fetchArray(SQLITE3_ASSOC);$waNote='';if($mm){$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'emi_rejected',['amount'=>number_format((float)$p['amount'],2),'txn'=>(string)$p['txn_id'],'reason'=>$reason]));$waNote=$wr[0]?' WhatsApp rejection message sent.':' WhatsApp नहीं भेजा जा सका: '.$wr[1];}$msg='EMI payment rejected.'.$waNote;}else{$msg='Rejection failed.';$msgType='danger';}}}}
    $focusId=(int)($_GET['focus']??0);$rows=$db->query("SELECT p.*,m.name,m.code,e.installment_no,e.due_date FROM payments p JOIN members m ON m.id=p.member_id LEFT JOIN emi_schedule e ON e.id=p.emi_id WHERE p.emi_id IS NOT NULL ORDER BY CASE WHEN p.id=".$focusId." THEN 0 ELSE 1 END,p.id DESC");
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">EMI COLLECTION</div><h1>EMI Payments</h1><p>Verify member EMI payments and update the repayment schedule. <span class="hi-sub">सदस्य के ईएमआई भुगतान सत्यापित करें और भुगतान अनुसूची अपडेट करें।</span></p></div></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="panel"><div class="table-wrap"><table><thead><tr><th>Member</th><th>EMI</th><th>Amount</th><th>Mode</th><th>Reference</th><th>Status / Action</th></tr></thead><tbody><?php while($r=$rows->fetchArray(SQLITE3_ASSOC)): ?><tr id="payment-<?=$r['id']?>" class="<?=((int)($_GET['focus']??0)===(int)$r['id'])?'focus-row':''?>"><td><b><?=h($r['name'])?></b><small class="block"><?=h($r['code'])?></small></td><td>#<?=h((string)$r['installment_no'])?><small class="block"><?=h($r['due_date']??'')?></small></td><td><?=money((float)$r['amount'])?></td><td><?=h($r['mode'])?></td><td><?=h($r['txn_id'])?></td><td><span class="badge <?=strtolower($r['status'])==='paid'?'success':(strtolower($r['status'])==='rejected'?'danger':'warning')?>"><?=h($r['status'])?></span><?php if($r['status']==='Paid'): ?><a class="receipt-link" href="?route=payment-receipt&type=emi&id=<?=$r['id']?>" target="_blank" rel="noopener">🧾 Slip</a> <a class="receipt-link" href="?route=send-payment-slip&type=emi&id=<?=$r['id']?>" target="_blank" rel="noopener">📤 Send Slip</a><?php endif; ?><?php if($r['status']==='Pending' && in_array(user()['role'],['admin','staff'],true)): ?><form class="inline-form" method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="id" value="<?=$r['id']?>"><input name="reject_reason" placeholder="Reject reason / कारण" style="min-width:180px"><button class="btn small primary" name="action" value="approve">Verify</button><button class="btn small danger" name="action" value="reject" onclick="return confirm('Reject करने के लिए कारण दर्ज करें?')">Reject</button></form><?php endif; ?><?php if($r['status']==='Rejected' && trim((string)($r['reject_reason']??''))!==''): ?><small class="block danger-text">Reason: <?=h($r['reject_reason'])?></small><?php endif; ?></td></tr><?php endwhile; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('EMI Payments',$c); exit;
}

if($route==='payment-api-callback'){
    // Generic gateway callback: provider must POST status, reference, payment_id and HMAC signature.
    $raw=file_get_contents('php://input'); $data=json_decode($raw,true);
    if(!is_array($data)) $data=$_POST;
    $secret=(string)getSetting('payment_api_secret'); $sig=(string)($_SERVER['HTTP_X_GS_SIGNATURE']??($data['signature']??''));
    if($secret===''){http_response_code(503);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Payment API secret is not configured']);exit;}
    $signed=['type'=>$data['type']??'emi','payment_id'=>$data['payment_id']??'','member_id'=>$data['member_id']??'','status'=>$data['status']??'','amount'=>$data['amount']??'','reference'=>$data['reference']??'','month'=>$data['month']??''];
    if(!hash_equals(hash_hmac('sha256',json_encode($signed,JSON_UNESCAPED_UNICODE),$secret),$sig)){http_response_code(401);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Invalid signature']);exit;}
    $status=strtolower((string)($data['status']??'')); $newStatus=in_array($status,['paid','success','successful'],true)?'Paid':'Rejected'; $ref=(string)($data['reference']??''); $type=strtolower((string)($data['type']??'emi'));
    if($type==='contribution'){
        $mid=(int)($data['member_id']??0); $amount=(float)($data['amount']??0); $month=trim((string)($data['month']??date('Y-m'))); if(!$mid||$amount<=0||!preg_match('/^\d{4}-(0[1-9]|1[0-2])$/',$month)){http_response_code(422);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Invalid contribution callback']);exit;} $memberExists=$db->prepare('SELECT id FROM members WHERE id=?');$memberExists->bindValue(1,$mid,SQLITE3_INTEGER);if(!$memberExists->execute()->fetchArray(SQLITE3_ASSOC)){http_response_code(422);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Unknown member']);exit;}
        if($ref!==''){ $dup=$db->prepare('SELECT id,status FROM contributions WHERE txn_id=? LIMIT 1');$dup->bindValue(1,$ref);$dr=$dup->execute()->fetchArray(SQLITE3_ASSOC); if($dr){header('Content-Type: application/json');echo json_encode(['ok'=>true,'status'=>$dr['status'],'duplicate'=>true]);exit;} }
        $st=$db->prepare('INSERT INTO contributions(member_id,amount,month,mode,status,txn_id,created_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)');$st->bindValue(1,$mid);$st->bindValue(2,$amount);$st->bindValue(3,$month);$st->bindValue(4,'Payment API');$st->bindValue(5,$newStatus);$st->bindValue(6,$ref);if(!$st->execute()){http_response_code(500);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Contribution could not be recorded']);exit;}
        header('Content-Type: application/json');echo json_encode(['ok'=>true,'status'=>$newStatus]);exit;
    }
    $pid=(int)($data['payment_id']??0);
    if(!$pid || !in_array($status,['paid','success','successful','failed','rejected'],true)){http_response_code(422);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Invalid callback']);exit;}
    $db->exec('BEGIN IMMEDIATE');
    try {
        $st=$db->prepare("UPDATE payments SET status=?,txn_id=CASE WHEN ?<>'' THEN ? ELSE txn_id END WHERE id=? AND status='Pending'");$st->bindValue(1,$newStatus);$st->bindValue(2,$ref);$st->bindValue(3,$ref);$st->bindValue(4,$pid);if(!$st->execute())throw new RuntimeException('Payment update failed.');$updated=$db->changes();
        if($updated===1&&$newStatus==='Paid'){$pp=$db->query("SELECT id,emi_id,amount,loan_id,created_at FROM payments WHERE id=".$pid)->fetchArray(SQLITE3_ASSOC);if($pp&&!empty($pp['emi_id'])){recordVerifiedEmiInterest($pp);$u=$db->prepare("UPDATE emi_schedule SET paid_amount=MIN(amount,paid_amount+?),status=CASE WHEN paid_amount+? >= amount THEN 'Paid' ELSE 'Pending' END WHERE id=?");$u->bindValue(1,(float)$pp['amount']);$u->bindValue(2,(float)$pp['amount']);$u->bindValue(3,(int)$pp['emi_id']);if(!$u->execute())throw new RuntimeException('EMI schedule update failed.');$loanId=(int)($pp['loan_id']??0);if($loanId>0){$close=$db->prepare("UPDATE loans SET status='Closed' WHERE id=? AND EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id) AND NOT EXISTS (SELECT 1 FROM emi_schedule e WHERE e.loan_id=loans.id AND MAX(e.amount-e.paid_amount,0)>0.009)");$close->bindValue(1,$loanId,SQLITE3_INTEGER);if(!$close->execute())throw new RuntimeException('Loan closure update failed');}}}
        $db->exec('COMMIT');
    }catch(Throwable $e){$db->exec('ROLLBACK');error_log('Payment callback processing failed: '.$e->getMessage());http_response_code(500);header('Content-Type: application/json');echo json_encode(['ok'=>false,'error'=>'Callback could not be processed']);exit;}
    header('Content-Type: application/json'); echo json_encode(['ok'=>true,'status'=>$newStatus]); exit;
}

if($route==='loan-affidavit'){
    requireRole(['admin','staff']);
    $lid=(int)($_GET['id']??0);
    $st=$db->prepare("SELECT l.*,m.name,m.code,m.mobile,m.address,m.email FROM loans l JOIN members m ON m.id=l.member_id WHERE l.id=?");
    $st->bindValue(1,$lid,SQLITE3_INTEGER); $loan=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$loan){http_response_code(404);exit('Loan not found');}
    $es=$db->query("SELECT * FROM emi_schedule WHERE loan_id=".$lid." ORDER BY installment_no");
    $emiRows=[]; $total=0; $paid=0;
    while($e=$es->fetchArray(SQLITE3_ASSOC)){ $emiRows[]=$e; $total+=(float)$e['amount']; $paid+=(float)$e['paid_amount']; }
    $monthly=emi((float)$loan['principal'],(float)$loan['interest_rate'],(int)$loan['tenure']);
    $soc=getSetting('society_name','GS Suraha Sahyog Samiti');
    ob_start(); ?>
    <style>
      .stamp-aff-wrap{width:215.9mm;max-width:100%;margin:0 auto;background:#fff}
      .stamp-page{position:relative;isolation:isolate;width:215.9mm;height:279.4mm;overflow:hidden;background:#fff;margin:0 auto}
      .stamp-page>img.stamp-bg{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;display:block;z-index:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .stamp-overlay{position:absolute;left:10.5%;right:10.5%;top:57.8%;bottom:2%;height:auto;overflow:visible;z-index:1;color:#111;font-family:Arial,"Noto Sans Devanagari",sans-serif;font-size:10.5pt;line-height:1.38}
      .stamp-overlay h2{text-align:center;font-size:13pt;margin:0 0 8px;font-weight:700}
      .stamp-overlay p{margin:0 0 6px;text-align:justify}
      .stamp-overlay .clause{display:flex;gap:5px;margin:0 0 4px;text-align:justify}
      .stamp-overlay .num{width:12px;flex:0 0 12px;font-weight:700}.stamp-overlay .txt{flex:1}
      .stamp-sign{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:12px;font-size:9pt}
      .stamp-cont{padding:18mm 14mm 16mm;font-family:Arial,"Noto Sans Devanagari",sans-serif;font-size:12pt;line-height:1.6;background:#fff;box-sizing:border-box}
      .stamp-cont h2{text-align:center;margin:0 0 12px;font-size:17pt}.stamp-cont p{margin:0 0 10px;text-align:justify}
      .stamp-cont .sig{display:grid;grid-template-columns:1fr 1fr;gap:30px;margin-top:28px}
      .stamp-actions{display:flex;gap:8px;justify-content:center;margin:0 0 12px}
      @media(max-width:650px){.stamp-overlay{font-size:9pt;line-height:1.3}.stamp-overlay h2{font-size:11pt}.stamp-overlay .clause{margin-bottom:3px}.stamp-sign{font-size:8pt}.stamp-cont{font-size:11pt;line-height:1.5}}
      @media print{
        @page{size:215.9mm 279.4mm;margin:0}
        html,body{margin:0!important;padding:0!important;background:#fff!important;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
        .page:has(.stamp-aff-wrap){max-width:none!important;padding:0!important;margin:0!important;overflow:visible!important}
        .stamp-actions,.no-print{display:none!important}
        .stamp-aff-wrap{width:215.9mm!important;max-width:none!important;margin:0!important}
        .stamp-page{position:relative!important;isolation:isolate!important;width:215.9mm!important;height:279.4mm!important;max-width:none!important;overflow:hidden!important;page-break-after:always!important;break-after:page!important;background:#fff!important;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
        .stamp-page>img.stamp-bg{display:block!important;position:absolute!important;inset:0!important;width:100%!important;height:100%!important;object-fit:fill!important;z-index:0!important;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
        .stamp-overlay{position:absolute!important;left:10.5%!important;right:10.5%!important;top:57.8%!important;bottom:2%!important;height:auto!important;overflow:visible!important;z-index:2!important;font-size:9.5pt!important;line-height:1.16!important;color:#111!important;}
        .stamp-overlay h2{font-size:12pt!important;margin:0 0 5px!important}
        .stamp-overlay p{margin:0 0 3px!important}
        .stamp-overlay .clause{margin:0 0 2px!important;gap:5px!important;break-inside:avoid!important;}
        .stamp-overlay .num{width:13px!important;flex-basis:13px!important}
        .stamp-sign{font-size:8.5pt!important;gap:8px!important;margin-top:7px!important;}
        .stamp-cont{width:215.9mm!important;height:279.4mm!important;min-height:279.4mm!important;overflow:hidden!important;border:0!important;page-break-after:always!important;break-after:page!important;box-sizing:border-box!important;padding:13mm!important;font-size:11pt!important;line-height:1.35!important;}
        .stamp-cont h2{font-size:15pt!important;margin:0 0 9px!important}
        .stamp-cont p{font-size:11pt!important;margin:0 0 7px!important}
        .stamp-cont .sig{font-size:10pt!important;gap:14px!important;margin-top:15px!important}
      }
    </style>
    <div class="stamp-aff-wrap">
      <div class="stamp-actions no-print">
        <a class="btn" href="?route=loans">← वापस Loans</a>
        <button class="btn primary" onclick="window.print()">🖨️ छापें / Download PDF</button>
      </div>
      <div class="stamp-page">
        <img class="stamp-bg" src="assets/affidavit/base.png" alt="Affidavit paper background" onerror="this.style.display='none'">
        <div class="stamp-overlay">
          <h2>AFFIDAVIT / शपथ-पत्र</h2>
          <p>मैं/हम, <b><?=h($loan['name'])?></b>, सदस्य आईडी <b><?=h($loan['code'])?></b>, GS Suraha के समक्ष दिए गए ऋण आवेदन एवं उससे संबंधित सभी विवरणों को सत्य एवं सही मानते हुए यह शपथ-पत्र प्रस्तुत करता/करती हूँ।</p>
          <div class="clause"><span class="num">1.</span><span class="txt">मेरे द्वारा दिए गए नाम, पता, मोबाइल नंबर तथा अन्य व्यक्तिगत विवरण सही हैं।</span></div>
          <div class="clause"><span class="num">2.</span><span class="txt">ऋण राशि <b><?=money((float)$loan['principal'])?></b>, अवधि <b><?=h((string)$loan['tenure'])?></b> माह, ब्याज <b><?=h((string)$loan['interest_rate'])?>%</b> एवं EMI <b><?=money($monthly)?></b> की शर्तें मुझे स्वीकार हैं।</span></div>
          <div class="clause"><span class="num">3.</span><span class="txt">मैं निर्धारित समय पर देय EMI एवं अन्य देय राशि का भुगतान करने के लिए सहमत हूँ।</span></div>
          <div class="clause"><span class="num">4.</span><span class="txt">मेरे द्वारा दी गई जानकारी या दस्तावेजों में कोई महत्वपूर्ण तथ्य छिपाया नहीं गया है।</span></div>
          <div class="clause"><span class="num">5.</span><span class="txt">भुगतान में विलंब होने पर संस्था के लागू नियम एवं शर्तें मुझ पर लागू होंगी।</span></div>
          <div class="clause"><span class="num">6.</span><span class="txt">ऋण खाते से संबंधित अभिलेख, भुगतान एवं EMI से जुड़े विवरण संस्था के रिकॉर्ड के अनुसार स्वीकार किए जाएंगे।</span></div>
          <div class="clause"><span class="num">7.</span><span class="txt">यह घोषणा मैंने अपनी स्वतंत्र इच्छा से, बिना किसी दबाव के की है।</span></div>
          <p><b>Declaration / घोषणा:</b> I confirm that the above information is true to the best of my knowledge and I agree to repay the sanctioned loan as per the recorded terms.</p>
          <div class="stamp-sign"><div>ऋणी/आवेदक हस्ताक्षर: __________________</div><div>दिनांक: ____ / ____ / ______</div></div>
        </div>
      </div>
      <div class="stamp-cont">
        <h2>Affidavit — Continuation / शपथ-पत्र — जारी</h2>
        <p><b>Member / सदस्य:</b> <?=h($loan['name'])?> &nbsp; <b>Member ID:</b> <?=h($loan['code'])?></p>
        <p><b>Loan No. / ऋण संख्या:</b> #<?=h((string)$loan['id'])?> &nbsp; <b>Loan Amount / ऋण राशि:</b> <?=money((float)$loan['principal'])?></p>
        <p>मैं यह भी स्वीकार करता/करती हूँ कि संस्था द्वारा मेरे ऋण, भुगतान और EMI से संबंधित रिकॉर्ड को सत्यापन एवं लेखा प्रयोजन के लिए सुरक्षित रखा जा सकता है।</p>
        <p>I hereby declare that the information stated above is true to the best of my knowledge. I undertake to use the sanctioned loan for the stated purpose and repay the scheduled EMI and any outstanding amount as per the terms recorded by the society.</p>
        <p>मैंने संस्था से प्राप्त ऋण राशि को स्वीकृत उद्देश्य के लिए उपयोग करने तथा निर्धारित शर्तों के अनुसार EMI का भुगतान करने की सहमति दी है। मैं प्रत्येक देय किस्त समय पर जमा करने और किसी भी बकाया राशि को संस्था के रिकॉर्ड के अनुसार चुकाने के लिए उत्तरदायी हूँ।</p>
        <div class="sig"><div>ऋणी/आवेदक<br><br>हस्ताक्षर: __________________________<br>नाम: <?=h($loan['name'])?></div><div>गवाह 1<br><br>हस्ताक्षर: __________________________</div></div>
        <div class="sig"><div>गवाह 2<br><br>हस्ताक्षर: __________________________</div><div>अधिकृत अधिकारी / Notary<br><br>हस्ताक्षर: __________________________</div></div>
        <p style="margin-top:22px;font-size:8.5pt">Affidavit No.: GS-SURAHA-AFF-<?=h((string)$loan['id'])?> · Date: <?=h(date('d-m-Y'))?></p>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Loan Affidavit',$c); exit;
}

if($route==='loan-pdf' || $route==='loan-agreement-pdf' || $route==='loan-agreement' || $route==='loan-summary'){
    requireRole(['admin','staff']);
    $lid=(int)($_GET['id']??0);
    $st=$db->prepare("SELECT l.*,m.name,m.code,m.mobile,m.address,m.email FROM loans l JOIN members m ON m.id=l.member_id WHERE l.id=?");
    $st->bindValue(1,$lid,SQLITE3_INTEGER); $loan=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$loan){http_response_code(404);exit('Loan not found');}
    $es=$db->query("SELECT * FROM emi_schedule WHERE loan_id=".$lid." ORDER BY installment_no");
    $emiRows=[]; $total=0; $paid=0; $pending=0; $paidCount=0; $next='';
    while($e=$es->fetchArray(SQLITE3_ASSOC)){ $emiRows[]=$e; $total+=(float)$e['amount']; $paid+=(float)$e['paid_amount']; if($e['status']==='Paid')$paidCount++;else{$pending++;if($next==='')$next=$e['due_date'];} }
    $outstanding=max(0,$total-$paid); $monthly=emi((float)$loan['principal'],(float)$loan['interest_rate'],(int)$loan['tenure']);
    $type=($route==='loan-pdf'||$route==='loan-summary')?'summary':(($route==='loan-affidavit')?'affidavit':'agreement');
    $soc=getSetting('society_name','GS Suraha Sahyog Samiti'); $tag=getSetting('society_tagline','Finance Co-operative Society');
    ob_start(); ?>
    <style id="gs-document-render-fix">
      .page:has(.document-preview-page){padding-left:12px!important;padding-right:12px!important;overflow-x:hidden!important}
      .document-preview-page{display:block!important;width:100%!important;max-width:900px!important;margin:0 auto!important;padding:8px 0 28px!important;box-sizing:border-box!important}
      .document-preview-page .official-document{display:block!important;width:100%!important;max-width:900px!important;min-width:0!important;margin:0!important;padding:18px!important;box-sizing:border-box!important;background:#fff!important;overflow:hidden!important}
      .document-preview-page .doc-header{display:flex!important;align-items:center!important;gap:12px!important;width:100%!important;box-sizing:border-box!important}
      .document-preview-page .doc-header img{display:block!important;width:64px!important;height:64px!important;min-width:64px!important;max-width:64px!important;min-height:64px!important;max-height:64px!important;object-fit:contain!important;object-position:center!important;flex:0 0 64px!important}
      .document-preview-page .doc-header>div{min-width:0!important;flex:1 1 auto!important}
      .document-preview-page .doc-header h1{font-size:21px!important;line-height:1.25!important;word-break:break-word!important}
      .document-preview-page .doc-box{width:100%!important;max-width:100%!important;box-sizing:border-box!important}
      .document-preview-page .doc-grid{width:100%!important;max-width:100%!important;box-sizing:border-box!important}
      .document-preview-page .table-wrap{width:100%!important;max-width:100%!important;overflow-x:auto!important}
      .document-preview-page .doc-table{width:100%!important;min-width:0!important}
      .document-preview-page .affidavit-title{text-align:center!important;border:1px solid #193b68!important}
      .document-preview-page .affidavit-title .doc-box-title{letter-spacing:.8px!important}
      .document-preview-page .affidavit-text p{margin:10px 0!important;text-align:justify!important}
      .document-preview-page .affidavit-sign{margin-top:30px!important}
      .document-preview-page .affidavit-witness{margin-top:16px!important}
      .document-preview-page .affidavit-note{font-size:9px!important;line-height:1.35!important;margin-top:14px!important}
      @media(max-width:650px){
        .page:has(.document-preview-page){padding-left:8px!important;padding-right:8px!important}
        .document-preview-page{width:100%!important;max-width:none!important;padding:6px 0 24px!important}
        .document-preview-page .official-document{width:100%!important;max-width:none!important;padding:12px!important;border-radius:12px!important}
        .document-preview-page .doc-header{gap:9px!important;padding:2px 0 10px!important}
        .document-preview-page .doc-header img{width:52px!important;height:52px!important;min-width:52px!important;max-width:52px!important;min-height:52px!important;max-height:52px!important;flex-basis:52px!important;border-radius:8px!important}
        .document-preview-page .doc-brand{font-size:8px!important;letter-spacing:1.2px!important}
        .document-preview-page .doc-header h1{font-size:17px!important;line-height:1.2!important;margin:2px 0!important}
        .document-preview-page .doc-header p{font-size:9px!important;line-height:1.3!important}
        .document-preview-page .doc-box{margin-top:9px!important}
        .document-preview-page .doc-box-title{font-size:10px!important;padding:7px 9px!important}
        .document-preview-page .doc-grid>div{padding:7px 9px!important}
        .document-preview-page .doc-grid small{font-size:7px!important}
        .document-preview-page .doc-grid b{font-size:10px!important;overflow-wrap:anywhere!important}
        .document-preview-page .summary-strip{padding:8px!important;gap:6px!important}
        .document-preview-page .summary-strip span{padding:7px!important;font-size:8px!important}
        .document-preview-page .summary-strip b{font-size:11px!important}
        .document-preview-page .official-document p{font-size:10px!important;line-height:1.5!important}
        .document-preview-page .signature-grid{gap:18px!important;margin:20px 5px 14px!important}
      }
      @media print{
        .page:has(.document-preview-page){padding:0!important;margin:0!important}
        .document-preview-page{width:100%!important;max-width:none!important;padding:0!important;margin:0!important}
        .document-preview-page .official-document{width:100%!important;max-width:none!important;margin:0!important;box-shadow:none!important;border:2px solid #193b68!important;border-radius:0!important}
        .document-preview-page .doc-header img{width:60px!important;height:60px!important;min-width:60px!important;max-width:60px!important;min-height:60px!important;max-height:60px!important;flex-basis:60px!important}
      }
    </style>
    <div class="document-preview-page"><div class="document-actions no-print"><a class="btn" href="?route=loans">← वापस Loans</a><button class="btn primary" onclick="window.print()">🖨️ Print / Save PDF</button></div>
    <article class="official-document">
      <header class="doc-header"><img src="assets/logo.png" alt="GS Suraha"><div><div class="doc-brand">GS SURAHA</div><h1><?= $type==='summary'?h(getSetting('doc_summary_title','EMI Loan Summary')).' / '.h(getSetting('doc_summary_subtitle','ईएमआई ऋण सारांश')):($type==='affidavit'?h(getSetting('doc_affidavit_title','AFFIDAVIT')).' / '.h(getSetting('doc_affidavit_subtitle','शपथ-पत्र')):h(getSetting('doc_agreement_title','Loan Agreement')).' / '.h(getSetting('doc_agreement_subtitle','ऋण समझौता'))) ?></h1><p><?=h($soc)?> · <?=h($tag)?></p></div></header>
      <?php if($type==='summary'): ?>
      <div class="doc-box"><div class="doc-box-title">Loan Details / ऋण विवरण</div><div class="doc-grid"><div><small>Loan ID / ऋण संख्या</small><b>#<?=h((string)$loan['id'])?></b></div><div><small>Date / दिनांक</small><b><?=h($loan['created_at'])?></b></div><div><small>Member / सदस्य</small><b><?=h($loan['name'])?> (<?=h($loan['code'])?>)</b></div><div><small>Mobile / मोबाइल</small><b><?=h($loan['mobile'])?></b></div><div><small>Principal / मूलधन</small><b><?=money((float)$loan['principal'])?></b></div><div><small>Interest / ब्याज</small><b><?=h((string)$loan['interest_rate'])?>%</b></div><div><small>Monthly EMI / मासिक किस्त</small><b><?=money($monthly)?></b></div><div><small>Tenure / अवधि</small><b><?=h((string)$loan['tenure'])?> months</b></div></div></div>
      <div class="doc-box"><div class="doc-box-title">EMI Summary / ईएमआई सारांश</div><div class="summary-strip"><span>Total EMI / कुल <b><?=money($total)?></b></span><span>Paid / जमा <b><?=money($paid)?></b></span><span>Outstanding / बकाया <b><?=money($outstanding)?></b></span><span>Paid Installments <b><?=$paidCount?> / <?=count($emiRows)?></b></span></div><div class="table-wrap"><table class="doc-table"><thead><tr><th>#</th><th>Due Date / तारीख</th><th>EMI</th><th>Paid</th><th>Status</th></tr></thead><tbody><?php foreach($emiRows as $e): ?><tr><td><?=h((string)$e['installment_no'])?></td><td><?=h($e['due_date'])?></td><td><?=money((float)$e['amount'])?></td><td><?=money((float)$e['paid_amount'])?></td><td><?=h($e['status'])?></td></tr><?php endforeach; ?></tbody></table></div></div>
            <?php elseif($type==='affidavit'): ?>
      <style>
        .stamp-aff-wrap{width:215.9mm;max-width:100%;margin:0 auto;background:#fff}
        .stamp-page{position:relative;isolation:isolate;width:215.9mm;height:279.4mm;overflow:hidden;background:#fff;margin:0 auto}
        .stamp-page>img.stamp-bg{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;display:block;z-index:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
        .stamp-overlay{position:absolute;left:10.5%;right:10.5%;top:57.8%;bottom:2%;height:auto;overflow:visible;z-index:1;color:#111;font-family:Arial,"Noto Sans Devanagari",sans-serif;font-size:10.5pt;line-height:1.38}
        .stamp-overlay h2{text-align:center;font-size:13pt;margin:0 0 8px;font-weight:700}
        .stamp-overlay p{margin:0 0 6px;text-align:justify}
        .stamp-overlay .clause{display:flex;gap:5px;margin:0 0 4px;text-align:justify}
        .stamp-overlay .num{width:12px;flex:0 0 12px;font-weight:700}
        .stamp-overlay .txt{flex:1}
        .stamp-sign{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:12px;font-size:9pt}
        .stamp-cont{padding:18mm 14mm 16mm;font-family:Arial,"Noto Sans Devanagari",sans-serif;font-size:12pt;line-height:1.6;background:#fff;border:1px solid #ddd;box-sizing:border-box}
        .stamp-cont h2{text-align:center;margin:0 0 12px;font-size:17pt}
        .stamp-cont p{margin:0 0 10px;text-align:justify}
        .stamp-cont .sig{display:grid;grid-template-columns:1fr 1fr;gap:30px;margin-top:28px}
        .stamp-actions{display:flex;gap:8px;justify-content:center;margin:0 0 12px}
        @media(max-width:650px){.stamp-page{transform-origin:top center}.stamp-overlay{font-size:9pt;line-height:1.3}.stamp-overlay h2{font-size:11pt}.stamp-overlay .clause{margin-bottom:3px}.stamp-sign{font-size:8pt}.stamp-cont{font-size:11pt;line-height:1.5}}
        @media print{
          @page{size:215.9mm 279.4mm;margin:0}
          body{margin:0!important;background:#fff!important}
          .stamp-actions,.no-print{display:none!important}
          .stamp-aff-wrap{width:215.9mm!important;max-width:none!important;margin:0!important}
          .page:has(.stamp-aff-wrap){max-width:none!important;padding:0!important;margin:0!important;overflow:visible!important}
          .stamp-page{position:relative!important;isolation:isolate!important;width:215.9mm!important;height:279.4mm!important;max-width:none!important;overflow:hidden!important;page-break-after:always!important;break-after:page!important;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
          .stamp-page>img.stamp-bg{display:block!important;position:absolute!important;inset:0!important;width:100%!important;height:100%!important;object-fit:fill!important;z-index:0!important;-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
          .stamp-overlay{position:absolute!important;left:10.5%!important;right:10.5%!important;top:57.8%!important;bottom:2%!important;height:auto!important;overflow:visible!important;z-index:2!important;font-size:9.5pt!important;line-height:1.18!important;color:#111!important;}
          .stamp-aff-wrap{width:215.9mm!important;max-width:none!important;margin:0!important}
          .stamp-cont{width:215.9mm!important;min-height:279.4mm!important;border:0!important;page-break-after:always!important;box-sizing:border-box!important}
        .stamp-overlay h2{font-size:12pt!important;margin-bottom:5px!important}
        .stamp-overlay p{margin-bottom:4px!important}
        .stamp-overlay .clause{margin-bottom:2px!important;gap:5px!important}
        .stamp-overlay .num{width:13px!important;flex-basis:13px!important}
        .stamp-sign{font-size:8.5pt!important;gap:10px!important;margin-top:8px!important}
        .stamp-cont{font-size:14pt!important;line-height:1.55!important;padding:16mm 13mm!important}
        .stamp-cont h2{font-size:19pt!important}
        .stamp-cont p{font-size:14pt!important;margin-bottom:12px!important}
        .stamp-cont .sig{font-size:12.5pt!important;gap:22px!important}
        }
      </style>
      <div class="stamp-aff-wrap">
        <div class="stamp-actions no-print">
          <a class="btn" href="?route=loans">← वापस Loans</a>
          <button class="btn primary" onclick="window.print()">🖨️ छापें / Download PDF</button>
        </div>
        <div class="stamp-page">
          <img class="stamp-bg" src="assets/affidavit/base.png" alt="Affidavit paper background" onerror="this.style.display='none'">
          <div class="stamp-overlay">
            <h2>AFFIDAVIT / शपथ-पत्र</h2>
            <p>मैं/हम, <b><?=h($loan['name'])?></b>, सदस्य आईडी <b><?=h($loan['code'])?></b>, GS Suraha के समक्ष दिए गए ऋण आवेदन एवं उससे संबंधित सभी विवरणों को सत्य एवं सही मानते हुए यह शपथ-पत्र प्रस्तुत करता/करती हूँ।</p>
            <div class="clause"><span class="num">1.</span><span class="txt">मेरे द्वारा दिए गए नाम, पता, मोबाइल नंबर तथा अन्य व्यक्तिगत विवरण सही हैं।</span></div>
            <div class="clause"><span class="num">2.</span><span class="txt">ऋण से संबंधित राशि <b><?=money((float)$loan['principal'])?></b>, अवधि <b><?=h((string)$loan['tenure'])?></b> माह, ब्याज <b><?=h((string)$loan['interest_rate'])?>%</b> एवं EMI <b><?=money($monthly)?></b> की शर्तें मुझे स्वीकार हैं।</span></div>
            <div class="clause"><span class="num">3.</span><span class="txt">मैं निर्धारित समय पर देय EMI एवं अन्य देय राशि का भुगतान करने के लिए सहमत हूँ।</span></div>
            <div class="clause"><span class="num">4.</span><span class="txt">मेरे द्वारा दी गई जानकारी या दस्तावेजों में कोई महत्वपूर्ण तथ्य छिपाया नहीं गया है।</span></div>
            <div class="clause"><span class="num">5.</span><span class="txt">भुगतान में विलंब होने पर संस्था के लागू नियम एवं शर्तें मुझ पर लागू होंगी।</span></div>
            <div class="clause"><span class="num">6.</span><span class="txt">ऋण खाते से संबंधित अभिलेख, भुगतान एवं EMI से जुड़े विवरण संस्था के रिकॉर्ड के अनुसार स्वीकार किए जाएंगे।</span></div>
            <div class="clause"><span class="num">7.</span><span class="txt">यह घोषणा मैंने अपनी स्वतंत्र इच्छा से, बिना किसी दबाव के की है।</span></div>
            <p><b>Declaration / घोषणा:</b> I confirm that the above information is true to the best of my knowledge and I agree to repay the sanctioned loan as per the recorded terms.</p>
            <div class="stamp-sign"><div>ऋणी/आवेदक हस्ताक्षर: __________________</div><div>दिनांक: ____ / ____ / ______</div></div>
          </div>
        </div>
        <div class="stamp-cont">
          <h2>Affidavit — Continuation / शपथ-पत्र — जारी</h2>
          <p><b>Member / सदस्य:</b> <?=h($loan['name'])?> &nbsp; <b>Member ID:</b> <?=h($loan['code'])?></p>
          <p><b>Loan No. / ऋण संख्या:</b> #<?=h((string)$loan['id'])?> &nbsp; <b>Loan Amount / ऋण राशि:</b> <?=money((float)$loan['principal'])?></p>
          <p>मैं यह भी स्वीकार करता/करती हूँ कि संस्था द्वारा मेरे ऋण, भुगतान और EMI से संबंधित रिकॉर्ड को सत्यापन एवं लेखा प्रयोजन के लिए सुरक्षित रखा जा सकता है।</p>
          <p>I hereby declare that the information stated above is true to the best of my knowledge. I undertake to use the sanctioned loan for the stated purpose and repay the scheduled EMI and any outstanding amount as per the terms recorded by the society.</p>
          <p>मैंने संस्था से प्राप्त ऋण राशि को स्वीकृत उद्देश्य के लिए उपयोग करने तथा निर्धारित शर्तों के अनुसार EMI का भुगतान करने की सहमति दी है। मैं प्रत्येक देय किस्त समय पर जमा करने और किसी भी बकाया राशि को संस्था के रिकॉर्ड के अनुसार चुकाने के लिए उत्तरदायी हूँ।</p>
          <div class="sig"><div>ऋणी/आवेदक<br><br>हस्ताक्षर: __________________________<br>नाम: <?=h($loan['name'])?></div><div>गवाह 1<br><br>हस्ताक्षर: __________________________</div></div>
          <div class="sig"><div>गवाह 2<br><br>हस्ताक्षर: __________________________</div><div>अधिकृत अधिकारी / Notary<br><br>हस्ताक्षर: __________________________</div></div>
          <p style="margin-top:22px;font-size:8.5pt">Affidavit No.: GS-SURAHA-AFF-<?=h((string)$loan['id'])?> · Date: <?=h(date('d-m-Y'))?></p>
        </div>
      </div>
      <?php else: ?>
      <div class="doc-box"><div class="doc-box-title">Borrower Details / उधारकर्ता विवरण</div><div class="doc-grid"><div><small>Agreement No. / समझौता संख्या</small><b>GS-SURAHA-LOAN-<?=h((string)$loan['id'])?></b></div><div><small>Agreement Date / दिनांक</small><b><?=h(date('d-m-Y'))?></b></div><div><small>Borrower / सदस्य</small><b><?=h($loan['name'])?></b></div><div><small>Member ID / सदस्य आईडी</small><b><?=h($loan['code'])?></b></div><div><small>Mobile / मोबाइल</small><b><?=h($loan['mobile'])?></b></div><div><small>Address / पता</small><b><?=h($loan['address'])?></b></div></div></div>
      <div class="doc-box"><div class="doc-box-title">Loan Terms / ऋण की शर्तें</div><p>सदस्य सहमत है कि स्वीकृत ऋण राशि का भुगतान निर्धारित EMI के अनुसार समय पर करेगा। प्रत्येक किस्त नियत तारीख तक जमा करना आवश्यक है। बकाया राशि का भुगतान पूर्ण होने तक देय रहेगी।</p><p>The borrower agrees to repay the loan through the scheduled EMI amounts on or before each due date. Payments are subject to verification by the society.</p><div class="doc-grid"><div><small>Loan Principal / ऋण राशि</small><b><?=money((float)$loan['principal'])?></b></div><div><small>Annual Interest / वार्षिक ब्याज</small><b><?=h((string)$loan['interest_rate'])?>%</b></div><div><small>Monthly EMI / मासिक किस्त</small><b><?=money($monthly)?></b></div><div><small>Total Repayment / कुल भुगतान</small><b><?=money($total)?></b></div></div></div>
      <div class="signature-grid"><div>Member Signature / सदस्य हस्ताक्षर<br><span>____________________________</span></div><div>Authorized Signatory / अधिकृत हस्ताक्षर<br><span>____________________________</span></div></div>
      <?php endif; ?>
      <footer class="doc-footer"><?=h($soc)?> · Secure · Transparent · Together</footer>
    </article></div>
    <?php $c=ob_get_clean(); layout($type==='summary'?'EMI Summary':'Loan Agreement',$c); exit;
}

if($route==='noc'){
    requireRole(['admin','staff','member']); $u=user(); $lid=(int)($_GET['id']??0);
    $sql="SELECT l.*,m.name,m.code,m.mobile,m.address FROM loans l JOIN members m ON m.id=l.member_id WHERE l.id=?";
    $st=$db->prepare($sql);$st->bindValue(1,$lid,SQLITE3_INTEGER);$loan=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$loan || ($u['role']==='member' && (int)$loan['member_id']!==(int)$u['member_id'])) exit('NOC not available.');
    $total=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM emi_schedule WHERE loan_id=".$lid);$paid=(float)$db->querySingle("SELECT COALESCE(SUM(paid_amount),0) FROM emi_schedule WHERE loan_id=".$lid);$out=max(0,$total-$paid);
    if($out>0.009) exit('NOC will be available after the loan is fully paid.');
    ob_start(); ?><style id="gs-noc-render-fix">
      .page:has(.document-preview-page){padding-left:12px!important;padding-right:12px!important;overflow-x:hidden!important}
      .document-preview-page{display:block!important;width:100%!important;max-width:900px!important;margin:0 auto!important;padding:8px 0 28px!important;box-sizing:border-box!important}
      .document-preview-page .official-document{display:block!important;width:100%!important;max-width:900px!important;min-width:0!important;padding:18px!important;box-sizing:border-box!important;background:#fff!important;overflow:hidden!important}
      .document-preview-page .doc-header{display:flex!important;align-items:center!important;gap:12px!important;width:100%!important}
      .document-preview-page .doc-header img{display:block!important;width:64px!important;height:64px!important;min-width:64px!important;max-width:64px!important;min-height:64px!important;max-height:64px!important;object-fit:contain!important;flex:0 0 64px!important}
      .document-preview-page .doc-header>div{min-width:0!important;flex:1 1 auto!important}
      .document-preview-page .doc-box,.document-preview-page .doc-grid{width:100%!important;max-width:100%!important;box-sizing:border-box!important}
      @media(max-width:650px){.page:has(.document-preview-page){padding-left:8px!important;padding-right:8px!important}.document-preview-page{width:100%!important;max-width:none!important}.document-preview-page .official-document{width:100%!important;max-width:none!important;padding:12px!important}.document-preview-page .doc-header img{width:52px!important;height:52px!important;min-width:52px!important;max-width:52px!important;min-height:52px!important;max-height:52px!important;flex-basis:52px!important}.document-preview-page .doc-header h1{font-size:17px!important}.document-preview-page .official-document p{font-size:10px!important;line-height:1.5!important}}
      @media print{.page:has(.document-preview-page){padding:0!important}.document-preview-page{width:100%!important;max-width:none!important;padding:0!important}.document-preview-page .official-document{width:100%!important;max-width:none!important;margin:0!important;box-shadow:none!important;border:2px solid #193b68!important;border-radius:0!important}}
    </style><div class="document-preview-page"><div class="document-actions no-print"><a class="btn" href="?route=loans">← वापस</a><button class="btn primary" onclick="window.print()">🖨️ Print / Save PDF</button></div><article class="official-document noc-document"><header class="doc-header"><img src="assets/logo.png" alt="GS Suraha"><div><div class="doc-brand">GS SURAHA</div><h1>NOC / अनापत्ति प्रमाण पत्र</h1><p><?=h(getSetting('society_name','GS Suraha Sahyog Samiti'))?></p></div></header><div class="noc-stamp">LOAN CLOSED · ऋण पूर्ण चुकता</div><div class="doc-box"><div class="doc-box-title">Member & Loan Details / सदस्य एवं ऋण विवरण</div><div class="doc-grid"><div><small>Member / सदस्य</small><b><?=h($loan['name'])?></b></div><div><small>Member ID</small><b><?=h($loan['code'])?></b></div><div><small>Loan No.</small><b>#<?=h((string)$loan['id'])?></b></div><div><small>Loan Amount</small><b><?=money((float)$loan['principal'])?></b></div><div><small>Total Paid</small><b><?=money($paid)?></b></div><div><small>Outstanding</small><b>₹0.00</b></div></div></div><div class="doc-box noc-text"><p>यह प्रमाणित किया जाता है कि उपरोक्त सदस्य ने संबंधित ऋण की सभी देय किस्तें/राशि पूर्ण रूप से जमा कर दी हैं। वर्तमान में इस ऋण के विरुद्ध कोई बकाया राशि नहीं है।</p><p>This is to certify that the above-mentioned loan has been fully repaid and there is no outstanding amount payable against this loan as of the date of issue.</p></div><div class="signature-grid"><div>Member Signature / सदस्य हस्ताक्षर<br><span>____________________________</span></div><div>Authorized Signatory / अधिकृत हस्ताक्षर<br><span>____________________________</span></div></div><footer class="doc-footer">Issued on / जारी दिनांक: <?=h(date('d-m-Y'))?></footer></article></div><?php $c=ob_get_clean();layout('Loan NOC',$c);exit;
}

if($route==='loans'){
    requireRole(['admin','staff']); $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=$_POST['action']??'';
        if($action==='delete'){
            if(user()['role']!=='admin'){ $msg='Only Admin can delete a loan.'; $msgType='danger'; }
            else {
                $lid=(int)($_POST['loan_id']??0);
                $db->exec('BEGIN');
                try{
                    $st=$db->prepare('DELETE FROM payments WHERE loan_id=?'); $st->bindValue(1,$lid,SQLITE3_INTEGER); $st->execute();
                    $st=$db->prepare('DELETE FROM emi_schedule WHERE loan_id=?'); $st->bindValue(1,$lid,SQLITE3_INTEGER); $st->execute();
                    $st=$db->prepare('DELETE FROM loans WHERE id=?'); $st->bindValue(1,$lid,SQLITE3_INTEGER); $st->execute();
                    if($db->changes()!==1) throw new RuntimeException('Loan not found.');
                    $db->exec('COMMIT'); $msg='Loan deleted successfully.';
                }catch(Throwable $e){$db->exec('ROLLBACK');$msg='Loan could not be deleted.';$msgType='danger';}
            }
        } elseif($action==='create') {
            $mid=(int)($_POST['member_id']??0);$p=(float)($_POST['principal']??0);$rate=(float)($_POST['interest_rate']??0);$n=(int)($_POST['tenure']??0);$purpose=trim($_POST['purpose']??'');
            if($p<=0||$n<1||$n>120){$msg='Enter valid principal and tenure (1-120 months).';$msgType='danger';}
            else {
                $db->exec('BEGIN');
                try{
                    $st=$db->prepare("INSERT INTO loans(member_id,principal,interest_rate,tenure,purpose) VALUES(?,?,?,?,?)");$st->bindValue(1,$mid);$st->bindValue(2,$p);$st->bindValue(3,$rate);$st->bindValue(4,$n);$st->bindValue(5,$purpose);if(!$st->execute())throw new RuntimeException('Loan insert failed');
                    $lid=(int)$db->lastInsertRowID();$schedule=loanAmortizationRows($p,$rate,$n);
                    foreach($schedule as $idx=>$part){$i=$idx+1;$st=$db->prepare("INSERT INTO emi_schedule(loan_id,installment_no,due_date,amount,principal_component,interest_component) VALUES(?,?,?,?,?,?)");$st->bindValue(1,$lid);$st->bindValue(2,$i);$st->bindValue(3,monthlyInstallmentDueDate($i));$st->bindValue(4,$part['amount']);$st->bindValue(5,$part['principal_component']);$st->bindValue(6,$part['interest_component']);if(!$st->execute())throw new RuntimeException('EMI insert failed');}
                    $db->exec('COMMIT');$msg='Loan created with EMI schedule.'; if(getSetting('whatsapp_auto_loan_disbursed_enabled','0')==='1'){ $mm=$db->query("SELECT id,name,mobile,code FROM members WHERE id=".(int)$mid)->fetchArray(SQLITE3_ASSOC); if($mm){$wr=whatsappSendTextToMember($mm,whatsappAutoTextForEvent($mm,'loan_disbursed',['amount'=>number_format($p,2),'loan_id'=>$lid])); if(!$wr[0])$msg.=' WhatsApp नहीं भेजा जा सका: '.$wr[1];}}
                }catch(Throwable $e){$db->exec('ROLLBACK');$msg='Loan creation failed.';$msgType='danger';}
            }
        }
    }
    $staffId=(user()['role']??'')==='staff'?(int)user()['id']:0;
    $loanScope=$staffId>0?" WHERE EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id=$staffId) ":" ";
    $loans=$db->query("SELECT l.*,m.name,m.code,
      COALESCE((SELECT SUM(amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) total_emi,
      COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) paid_emi,
      COALESCE((SELECT SUM(MAX(amount-paid_amount,0)) FROM emi_schedule e WHERE e.loan_id=l.id),0) outstanding,
      COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status='Paid'),0) paid_count,
      COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid'),0) pending_count,
      (SELECT due_date FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid' ORDER BY e.installment_no LIMIT 1) next_due
      FROM loans l JOIN members m ON m.id=l.member_id".$loanScope."ORDER BY l.id DESC");
    $members=$db->query("SELECT m.id,m.code,m.name FROM members m WHERE m.status='Active'".($staffId>0?" AND EXISTS (SELECT 1 FROM staff_member_assignments sma WHERE sma.member_id=m.id AND sma.staff_id=$staffId)":"")." ORDER BY m.name");
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">LOAN PORTFOLIO</div><h1>Loans & EMI</h1><p>Active loan book, EMI summary and repayment control. <span class="hi-sub">सक्रिय ऋण, ईएमआई सारांश और भुगतान नियंत्रण।</span></p></div></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-3"><div class="panel"><h2>Create Loan</h2><form method="post"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="create"><label>Member</label><select name="member_id"><?php while($m=$members->fetchArray(SQLITE3_ASSOC)): ?><option value="<?=$m['id']?>"><?=h($m['code'].' — '.$m['name'])?></option><?php endwhile; ?></select><label>Principal</label><input name="principal" type="number" step="0.01" required><label>Annual Interest %</label><input name="interest_rate" type="number" step="0.01" value="12" required><label>Tenure</label><input name="tenure" type="number" value="12" min="1" max="120" required><label>Purpose</label><input name="purpose"><button class="btn primary full">Create Loan</button></form></div>
    <div class="panel span2"><h2>Loan Book</h2><div class="table-wrap"><table><thead><tr><th>Member</th><th>Principal</th><th>EMI</th><th>EMI Summary</th><th>Outstanding</th><th>Actions</th></tr></thead><tbody><?php while($l=$loans->fetchArray(SQLITE3_ASSOC)): $monthly=emi((float)$l['principal'],(float)$l['interest_rate'],(int)$l['tenure']); ?><tr><td><b><?=h($l['code'].' — '.$l['name'])?></b><small class="block">Loan #<?=$l['id']?></small></td><td><?=money((float)$l['principal'])?><small class="block"><?=h($l['interest_rate'])?>% · <?=h($l['tenure'])?> mo</small></td><td><?=money($monthly)?></td><td><div class="emi-summary-modern"><span class="emi-pill paid">✓ <?=h((string)$l['paid_count'])?> Paid</span><span class="emi-pill pending">⌛ <?=h((string)$l['pending_count'])?> Pending</span><small>Total <?=money((float)$l['total_emi'])?> · Paid <?=money((float)$l['paid_emi'])?> · Next <?=h($l['next_due']?:'None')?></small></div></td><td><?=money((float)$l['outstanding'])?></td><td><div class="inline-form"><a class="btn small" href="?route=loan-summary&id=<?=$l['id']?>">EMI Summary</a><a class="btn small" href="?route=loan-agreement&id=<?=$l['id']?>">Agreement</a><a class="btn small" href="?route=loan-affidavit&id=<?=$l['id']?>">Affidavit</a><?php if((float)$l['outstanding']<=0.009): ?><a class="btn small" href="?route=noc&id=<?=$l['id']?>">NOC</a><?php endif; ?><?php if(user()['role']==='admin'): ?><form method="post" onsubmit="return confirm('Delete this loan and its EMI/payment records? This cannot be undone.');"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="loan_id" value="<?=$l['id']?>"><button class="btn small danger">Delete</button></form><?php endif; ?></div></td></tr><?php endwhile; ?></tbody></table></div></div></div>
    <?php $c=ob_get_clean(); layout('Loans & EMI',$c); exit;
}

if($route==='member-excel'){
    requireRole(['admin','staff']); $mid=(int)($_GET['member_id']??0); $where=$mid>0?'WHERE m.id='.$mid:'';
    $rows=$db->query("SELECT m.code,m.name,m.mobile,m.email,m.address,m.status,COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) contribution_total,COALESCE((SELECT SUM(principal) FROM loans l WHERE l.member_id=m.id),0) loan_principal,COALESCE((SELECT SUM(amount) FROM emi_schedule e JOIN loans l2 ON l2.id=e.loan_id WHERE l2.member_id=m.id),0) emi_total,COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e JOIN loans l3 ON l3.id=e.loan_id WHERE l3.member_id=m.id),0) emi_paid,COALESCE((SELECT SUM(MAX(e.amount-e.paid_amount,0)) FROM emi_schedule e JOIN loans l4 ON l4.id=e.loan_id WHERE l4.member_id=m.id),0) emi_outstanding,COALESCE((SELECT SUM(il.amount) FROM member_interest_ledger il WHERE il.member_id=m.id),0) interest_earned FROM members m $where ORDER BY m.name");
    header('Content-Type: text/csv; charset=UTF-8'); header('Content-Disposition: attachment; filename=gs_suraha_member_report_'.date('Ymd_His').'.csv'); header('Pragma: no-cache'); echo "\xEF\xBB\xBF"; $out=fopen('php://output','w'); fputcsv($out,['Member ID','Name','Mobile','Email','Address','Status','Contribution Total','Loan Principal','Interest Earned','EMI Total','EMI Paid','EMI Outstanding']); while($r=$rows->fetchArray(SQLITE3_ASSOC)) fputcsv($out,[$r['code'],$r['name'],$r['mobile'],$r['email'],$r['address'],$r['status'],number_format((float)$r['contribution_total'],2,'.',''),number_format((float)$r['loan_principal'],2,'.',''),number_format((float)$r['interest_earned'],2,'.',''),number_format((float)$r['emi_total'],2,'.',''),number_format((float)$r['emi_paid'],2,'.',''),number_format((float)$r['emi_outstanding'],2,'.','')]); fclose($out); exit;
}

if($route==='backup'){
    requireRole(['admin']);
    if(!is_file(DB_FILE)){ http_response_code(404); exit('Database not found.'); }
    if(function_exists('ob_get_level')) while(ob_get_level()>0) ob_end_clean();
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="gs_suraha_backup_'.date('Ymd_His').'.sqlite"');
    header('Content-Length: '.filesize(DB_FILE));
    header('Cache-Control: no-store');
    readfile(DB_FILE); exit;
}

if($route==='reports-excel'){
    requireRole(['admin','staff']);
    $active=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");
    $loanCount=(int)$db->querySingle("SELECT COUNT(*) FROM loans");
    $dep=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'");
    $loan=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans");
    $verified=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Paid'");
    $pending=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Pending'");
    $emiTotal=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM emi_schedule");
    $emiPaid=(float)$db->querySingle("SELECT COALESCE(SUM(paid_amount),0) FROM emi_schedule");
    $emiOut=max(0,$emiTotal-$emiPaid);
    $paidCount=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status='Paid'");
    $pendingCount=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status!='Paid'");
    $metrics=[['Active Members',$active],['Loans',$loanCount],['Total Contributions Paid','Rs. '.number_format($dep,2)],['Loan Principal','Rs. '.number_format($loan,2)],['Verified Payments','Rs. '.number_format($verified,2)],['Pending Payments','Rs. '.number_format($pending,2)],['EMI Scheduled','Rs. '.number_format($emiTotal,2)],['EMI Paid','Rs. '.number_format($emiPaid,2)],['EMI Outstanding','Rs. '.number_format($emiOut,2)],['Paid EMI',$paidCount]];
    $reportRows=[];$reportRows[]=['__style'=>'Title','__cells'=>['GS SURAHA SAHYOG SAMITI']];$reportRows[]=['__style'=>'Subtitle','__cells'=>['Financial Management System']];$reportRows[]=['__cells'=>['Report Type','GS Suraha Finance - Report','Generated On',date('d-m-Y h:i A')]];$reportRows[]=['__cells'=>['Organization',getSetting('society_name','GS Suraha Sahyog Samiti')]];$reportRows[]=['__style'=>'Section','__cells'=>['FINANCIAL OVERVIEW']];$reportRows[]=['__style'=>'Header','__cells'=>['Metric','Value','Metric','Value','Metric','Value','Metric','Value','Metric','Value']];
    for($i=0;$i<count($metrics);$i+=5){$cells=[];for($k=0;$k<5;$k++){$cells[]=$metrics[$i+$k][0]??'';$cells[]=$metrics[$i+$k][1]??'';}$reportRows[]=$cells;}
    $reportRows[]=['__style'=>'Section','__cells'=>['LOAN SUMMARY']];$reportRows[]=['__style'=>'Header','__cells'=>['Loan ID','Member ID','Member Name','Principal','EMI Total','EMI Paid','Outstanding','Paid EMI','Pending EMI']];
    $loanRows=[];$lr=$db->query("SELECT l.id,m.code,m.name,l.principal,COALESCE((SELECT SUM(amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) total_emi,COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) paid_emi,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status='Paid'),0) paid_count,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid'),0) pending_count FROM loans l JOIN members m ON m.id=l.member_id ORDER BY l.id DESC");while($lr&&($x=$lr->fetchArray(SQLITE3_ASSOC))){$out=max(0,(float)$x['total_emi']-(float)$x['paid_emi']);$rr=[$x['id'],$x['code'],$x['name'],number_format((float)$x['principal'],2),number_format((float)$x['total_emi'],2),number_format((float)$x['paid_emi'],2),number_format($out,2),$x['paid_count'],$x['pending_count']];$loanRows[]=$rr;$reportRows[]=$rr;}if(!$loanRows)$reportRows[]=['No loan records found. Loan summary is empty because no loans exist in the database.'];
    $contribCount=(int)$db->querySingle("SELECT COUNT(*) FROM contributions");$paymentCount=(int)$db->querySingle("SELECT COUNT(*) FROM payments");$fundCount=(int)$db->querySingle("SELECT COUNT(*) FROM fund_adjustments");$interestCollected=(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections");$interestAllocated=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger");$interestUnallocated=max(0,$interestCollected-$interestAllocated);
    $reportRows[]=['__style'=>'Section','__cells'=>['PAYMENT SUMMARY']];$reportRows[]=['__cells'=>['Payment records',$paymentCount]];$reportRows[]=['__cells'=>['Contribution records',$contribCount]];$reportRows[]=['__cells'=>['Fund adjustment records',$fundCount]];$reportRows[]=['__cells'=>['Loan interest collected','Rs. '.number_format($interestCollected,2)]];$reportRows[]=['__cells'=>['Interest credited to members','Rs. '.number_format($interestAllocated,2)]];$reportRows[]=['__cells'=>['Interest not yet allocated','Rs. '.number_format($interestUnallocated,2)]];
    $reportRows[]=['__style'=>'Section','__cells'=>['MEMBER SUMMARY']];$reportRows[]=['__style'=>'Header','__cells'=>['S.No','Member ID','Name','Mobile No.','Total Savings','Total Loan','Interest Earned','EMI Due','Paid Amount','Status']];
    $memberRows=[];$mr=$db->query("SELECT m.code,m.name,m.mobile,m.status,COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) contribution_total,COALESCE((SELECT SUM(principal) FROM loans l WHERE l.member_id=m.id),0) loan_principal,COALESCE((SELECT SUM(MAX(e.amount-e.paid_amount,0)) FROM emi_schedule e JOIN loans l2 ON l2.id=e.loan_id WHERE l2.member_id=m.id),0) emi_outstanding,COALESCE((SELECT SUM(e.paid_amount) FROM emi_schedule e JOIN loans l3 ON l3.id=e.loan_id WHERE l3.member_id=m.id),0) emi_paid,COALESCE((SELECT SUM(il.amount) FROM member_interest_ledger il WHERE il.member_id=m.id),0) interest_earned FROM members m ORDER BY m.name COLLATE NOCASE");$serial=0;while($mr&&($x=$mr->fetchArray(SQLITE3_ASSOC))){$serial++;$rr=[$serial,$x['code'],$x['name'],$x['mobile'],'Rs. '.number_format((float)$x['contribution_total'],2),'Rs. '.number_format((float)$x['loan_principal'],2),'Rs. '.number_format((float)$x['interest_earned'],2),'Rs. '.number_format((float)$x['emi_outstanding'],2),'Rs. '.number_format((float)$x['emi_paid'],2),$x['status']];$memberRows[]=$rr;$reportRows[]=$rr;}
    $sheets=['Report Summary'=>['rows'=>$reportRows,'widths'=>[45,65,120,90,90,90,90,85,85,85]]];
    $sheets['Members']=['headers'=>['S.No','Member ID','Name','Mobile','Status','Total Savings','Total Loan','Interest Earned','EMI Due','Paid Amount'],'rows'=>$memberRows,'widths'=>[45,75,150,100,70,90,90,95,90,90]];
    $sheets['Loans EMI']=['headers'=>['Loan ID','Member ID','Member Name','Principal','EMI Total','EMI Paid','Outstanding','Paid EMI','Pending EMI'],'rows'=>$loanRows,'widths'=>[60,80,145,85,85,85,85,70,80]];
    $rows=[];$r=$db->query("SELECT p.id,m.code,m.name,p.amount,p.mode,p.txn_id,p.status,p.reject_reason,p.created_at FROM payments p JOIN members m ON m.id=p.member_id ORDER BY p.id DESC");while($r&&($x=$r->fetchArray(SQLITE3_NUM)))$rows[]=$x;$sheets['Payments']=['headers'=>['Payment ID','Member ID','Member','Amount','Mode','Txn ID','Status','Reject Reason','Created'],'rows'=>$rows,'widths'=>[65,80,140,85,85,140,75,180,130]];
    $rows=[];$r=$db->query("SELECT c.id,m.code,m.name,c.amount,c.month,c.mode,c.txn_id,c.status,c.reject_reason,c.created_at FROM contributions c JOIN members m ON m.id=c.member_id ORDER BY c.id DESC");while($r&&($x=$r->fetchArray(SQLITE3_NUM)))$rows[]=$x;$sheets['Contributions']=['headers'=>['ID','Member ID','Member','Amount','Month','Mode','Txn ID','Status','Reject Reason','Created'],'rows'=>$rows,'widths'=>[55,80,140,85,80,85,140,75,180,130]];
    $rows=[];$r=$db->query("SELECT f.id,f.type,f.amount,f.note,f.created_at,COALESCE(u.username,'') FROM fund_adjustments f LEFT JOIN users u ON u.id=f.created_by ORDER BY f.id DESC");while($r&&($x=$r->fetchArray(SQLITE3_NUM)))$rows[]=$x;$sheets['Fund Adjustments']=['headers'=>['ID','Type','Amount','Note','Created','Created By'],'rows'=>$rows,'widths'=>[55,90,90,220,140,110]];
    $rows=[];$r=$db->query("SELECT ic.id,ic.created_at,ic.source_payment_id,ic.loan_id,ic.emi_id,ic.interest_amount,ic.contribution_basis_total,COALESCE(SUM(il.amount),0) FROM interest_collections ic LEFT JOIN member_interest_ledger il ON il.interest_collection_id=ic.id GROUP BY ic.id ORDER BY ic.id DESC");while($r&&($x=$r->fetchArray(SQLITE3_NUM)))$rows[]=$x;$sheets['Interest Collections']=['headers'=>['Collection ID','Collected At','Payment ID','Loan ID','EMI ID','Loan Interest Collected','Contribution Basis','Interest Allocated'],'rows'=>$rows,'widths'=>[80,140,80,70,70,120,120,110]];
    $rows=[];$r=$db->query("SELECT ic.created_at,ic.source_payment_id,ic.loan_id,ic.emi_id,m.code,m.name,il.contribution_basis,il.total_contribution_basis,il.amount FROM member_interest_ledger il JOIN interest_collections ic ON ic.id=il.interest_collection_id JOIN members m ON m.id=il.member_id ORDER BY ic.id DESC,m.name COLLATE NOCASE");while($r&&($x=$r->fetchArray(SQLITE3_NUM)))$rows[]=$x;$sheets['Member Interest Ledger']=['headers'=>['Credited At','Payment ID','Loan ID','EMI ID','Member ID','Member Name','Member Contribution Basis','Total Contribution Basis','Interest Credited'],'rows'=>$rows,'widths'=>[140,80,70,70,80,150,130,130,110]];
    sendExcelWorkbook('gs_suraha_financial_report_'.date('Ymd_His').'.xls',$sheets);
}

if($route==='report-pdf'){
    requireRole(['admin','staff']);
    $active=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");$loanCount=(int)$db->querySingle("SELECT COUNT(*) FROM loans");
    $dep=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'");$loan=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans");$verified=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Paid'");$pending=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Pending'");
    $emiTotal=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM emi_schedule");$emiPaid=(float)$db->querySingle("SELECT COALESCE(SUM(paid_amount),0) FROM emi_schedule");$emiOut=max(0,$emiTotal-$emiPaid);$paidCount=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status='Paid'");
    $metrics=[['Active Members',(string)$active],['Loans',(string)$loanCount],['Total Contributions Paid','Rs. '.number_format($dep,2)],['Loan Principal','Rs. '.number_format($loan,2)],['Verified Payments','Rs. '.number_format($verified,2)],['Pending Payments','Rs. '.number_format($pending,2)],['EMI Scheduled','Rs. '.number_format($emiTotal,2)],['EMI Paid','Rs. '.number_format($emiPaid,2)],['EMI Outstanding','Rs. '.number_format($emiOut,2)],['Paid EMI',(string)$paidCount]];
    $loans=[];$q=$db->query("SELECT l.id,m.code,m.name,l.principal,COALESCE((SELECT SUM(amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) total_emi,COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) paid_emi,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status='Paid'),0) paid_count,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid'),0) pending_count FROM loans l JOIN members m ON m.id=l.member_id ORDER BY l.id DESC");while($q&&($x=$q->fetchArray(SQLITE3_ASSOC)))$loans[]=$x;
    $paymentSummary=['Payment records'=>(string)$db->querySingle("SELECT COUNT(*) FROM payments"),'Contribution records'=>(string)$db->querySingle("SELECT COUNT(*) FROM contributions"),'Fund adjustment records'=>(string)$db->querySingle("SELECT COUNT(*) FROM fund_adjustments"),'Loan interest collected'=>'Rs. '.number_format((float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections"),2),'Interest credited to members'=>'Rs. '.number_format((float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger"),2),'Interest not yet allocated'=>'Rs. '.number_format(max(0,(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections")-(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger")),2)];
    $members=[];$q=$db->query("SELECT m.code,m.name,m.mobile,m.status,COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) contribution_total,COALESCE((SELECT SUM(principal) FROM loans l WHERE l.member_id=m.id),0) loan_principal,COALESCE((SELECT SUM(MAX(e.amount-e.paid_amount,0)) FROM emi_schedule e JOIN loans l2 ON l2.id=e.loan_id WHERE l2.member_id=m.id),0) emi_outstanding,COALESCE((SELECT SUM(e.paid_amount) FROM emi_schedule e JOIN loans l3 ON l3.id=e.loan_id WHERE l3.member_id=m.id),0) emi_paid,COALESCE((SELECT SUM(il.amount) FROM member_interest_ledger il WHERE il.member_id=m.id),0) interest_earned FROM members m ORDER BY m.name COLLATE NOCASE");while($q&&($x=$q->fetchArray(SQLITE3_ASSOC)))$members[]=$x;
    sendFinancialReportPdf('gs_suraha_report_'.date('Ymd_His').'.pdf',getSetting('society_name','GS Suraha Sahyog Samiti'),$metrics,$loans,$paymentSummary,$members);
}

if($route==='member-closure-report'){
    requireRole(['admin','staff']);
    $rows=$db->query("SELECT mc.*,m.code,m.name,m.mobile,u.username AS approved_username FROM member_closures mc JOIN members m ON m.id=mc.member_id LEFT JOIN users u ON u.id=mc.approved_by ORDER BY mc.id DESC");
    $totalRefund=(float)$db->querySingle("SELECT COALESCE(SUM(refund_amount),0) FROM member_closures WHERE status='Approved'"); $pending=(int)$db->querySingle("SELECT COUNT(*) FROM member_closures WHERE status='Pending'");
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">CLOSURE & REFUND REPORT</div><h1>Member Closure / Refund Report</h1><p>Closed members, proportionate interest and final refunds. / सदस्य बंद होने और refund की पूरी रिपोर्ट।</p></div><a class="btn" href="?route=reports">← Reports</a></div><div class="kpis"><div class="kpi red"><span>Total Refund Approved</span><b><?=money($totalRefund)?></b></div><div class="kpi orange"><span>Pending Requests</span><b><?=$pending?></b></div></div><div class="panel"><div class="panel-head"><h2>Closure History</h2><a class="btn small" href="?route=member-closure-report-excel">⬇ Excel</a></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Member</th><th>Contribution</th><th>Interest Pool</th><th>Member Interest</th><th>Deduction</th><th>Refund</th><th>Status</th><th>Approved By</th></tr></thead><tbody><?php $has=false; while($r=$rows->fetchArray(SQLITE3_ASSOC)){$has=true; ?><tr><td><?=h($r['created_at'])?></td><td><b><?=h($r['name'])?></b><small class="block"><?=h($r['code'])?></small></td><td><?=money((float)$r['contribution_total'])?></td><td><?=money((float)$r['interest_pool'])?></td><td><?=money((float)$r['member_interest'])?></td><td><?=money((float)$r['deductions'])?></td><td><b><?=money((float)$r['refund_amount'])?></b></td><td><span class="badge <?=($r['status']==='Approved'?'success':'warning')?>"><?=h($r['status'])?></span></td><td><?=h($r['approved_username']??'—')?></td></tr><?php } if(!$has): ?><tr><td colspan="9">No closure/refund records yet.</td></tr><?php endif; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('Member Closure Refund Report',$c); exit;
}
if($route==='member-closure-report-excel'){
    requireRole(['admin','staff']); $rows=$db->query("SELECT mc.created_at,m.code,m.name,mc.contribution_total,mc.interest_pool,mc.member_interest,mc.deductions,mc.refund_amount,mc.status,u.username approved_by FROM member_closures mc JOIN members m ON m.id=mc.member_id LEFT JOIN users u ON u.id=mc.approved_by ORDER BY mc.id DESC"); $data=['headers'=>['Date','Member ID','Member','Contribution','Interest Pool','Member Interest','Deduction','Refund','Status','Approved By'],'rows'=>[]]; while($r=$rows->fetchArray(SQLITE3_ASSOC)) $data['rows'][]=[$r['created_at'],$r['code'],$r['name'],number_format((float)$r['contribution_total'],2),number_format((float)$r['interest_pool'],2),number_format((float)$r['member_interest'],2),number_format((float)$r['deductions'],2),number_format((float)$r['refund_amount'],2),$r['status'],$r['approved_by']??'']; sendExcelWorkbook('member_closure_refund_report_'.date('Ymd_His').'.xml',['Closure Refund Report'=>$data]);
}

if($route==='reports'){
    requireRole(['admin','staff']);
    $dep=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM contributions WHERE status='Paid'");
    $loan=(float)$db->querySingle("SELECT COALESCE(SUM(principal),0) FROM loans");
    $paid=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Paid'");
    $pending=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Pending'");
    $emiTotal=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM emi_schedule");
    $emiPaid=(float)$db->querySingle("SELECT COALESCE(SUM(paid_amount),0) FROM emi_schedule");
    $emiOutstanding=max(0,$emiTotal-$emiPaid);
    $emiPaidCount=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status='Paid'");
    $emiPendingCount=(int)$db->querySingle("SELECT COUNT(*) FROM emi_schedule WHERE status!='Paid'");
    $loanCount=(int)$db->querySingle("SELECT COUNT(*) FROM loans");
    $memberCount=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");$interestCollected=(float)$db->querySingle("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections");$interestAllocated=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger");
    $rows=$db->query("SELECT l.id,m.code,m.name,l.principal,l.interest_rate,l.tenure,COALESCE((SELECT SUM(amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) total_emi,COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e WHERE e.loan_id=l.id),0) paid_emi,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status='Paid'),0) paid_count,COALESCE((SELECT COUNT(*) FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid'),0) pending_count,(SELECT due_date FROM emi_schedule e WHERE e.loan_id=l.id AND e.status!='Paid' ORDER BY e.installment_no LIMIT 1) next_due FROM loans l JOIN members m ON m.id=l.member_id ORDER BY l.id DESC");
    ob_start(); ?>
    <div class="page-title">
      <div>
        <div class="eyebrow">REPORT CENTER</div>
        <h1>Reports & Summary</h1>
        <p>Live contribution, loan, payment and EMI report. <span class="hi-sub">जमा, ऋण, भुगतान और ईएमआई की लाइव रिपोर्ट।</span></p>
      </div>
      <div class="inline-form report-actions">
        <a class="btn btn-excel" href="?route=reports-excel">⬇ Excel Report</a>
        <a class="btn btn-pdf primary" target="_blank" href="?route=report-pdf">⬇ PDF Report</a>
        <a class="btn" href="?route=member-closure-report">🔒 Closure/Refund</a>
        <a class="btn" href="?route=member-excel">⬇ Member Excel</a>
      </div>
    </div>

    <div class="kpis report-kpis">
      <div class="kpi green"><span>Contributions Paid</span><b><?=money($dep)?></b></div>
      <div class="kpi purple"><span>Loan Principal</span><b><?=money($loan)?></b></div>
      <div class="kpi blue"><span>Payments Verified</span><b><?=money($paid)?></b></div>
      <div class="kpi orange"><span>Payments Pending</span><b><?=money($pending)?></b></div>
      <div class="kpi pink"><span>Active Members</span><b><?=$memberCount?></b></div>
      <div class="kpi red"><span>Total Loans</span><b><?=$loanCount?></b></div>
      <div class="kpi teal"><span>Loan Interest Collected</span><b><?=money($interestCollected)?></b><small>Member allocation <?=money($interestAllocated)?></small></div>
    </div>
    <div class="grid-3 report-summary-grid"><div class="panel report-card"><div class="report-card-title"><h2>EMI Summary</h2><span class="badge success">Live</span></div><div class="report-stats"><div><span>Total Scheduled</span><b><?=money($emiTotal)?></b></div><div><span>Total Paid</span><b><?=money($emiPaid)?></b></div><div><span>Outstanding</span><b><?=money($emiOutstanding)?></b></div><div><span>Installments</span><b><?=$emiPaidCount?> paid · <?=$emiPendingCount?> pending</b></div></div></div><div class="panel report-card"><div class="report-card-title"><h2>Payment Summary</h2></div><div class="report-stats"><div><span>Verified</span><b><?=money($paid)?></b></div><div><span>Pending</span><b><?=money($pending)?></b></div><div><span>All Recorded</span><b><?=money($paid+$pending)?></b></div></div></div><div class="panel report-card"><div class="report-card-title"><h2>Portfolio</h2></div><div class="report-stats"><div><span>Members</span><b><?=$memberCount?></b></div><div><span>Loans</span><b><?=$loanCount?></b></div><div><span>Principal</span><b><?=money($loan)?></b></div></div></div></div>
    <div class="panel report-loan-panel"><div class="panel-head"><h2>Loan-wise EMI Report</h2><span class="badge">Paid / Pending / Outstanding</span></div><div class="table-wrap"><table class="mobile-card-table report-loan-table"><thead><tr><th>Loan</th><th>Member</th><th>Principal</th><th>EMI Summary</th><th>Outstanding</th><th>Next Due</th></tr></thead><tbody><?php if($rows && $rows->numColumns()>0): $has=false; while($r=$rows->fetchArray(SQLITE3_ASSOC)): $has=true; $out=max(0,(float)$r['total_emi']-(float)$r['paid_emi']); ?><tr><td data-label="Loan"><b>#<?=h((string)$r['id'])?></b><small class="block"><?=h((string)$r['interest_rate'])?>% · <?=h((string)$r['tenure'])?> mo</small></td><td data-label="Member"><b><?=h($r['name'])?></b><small class="block"><?=h($r['code'])?></small></td><td data-label="Principal"><?=money((float)$r['principal'])?></td><td data-label="EMI Summary"><div class="emi-summary-modern"><span class="emi-pill paid">✓ <?=$r['paid_count']?> Paid</span><span class="emi-pill pending">⌛ <?=$r['pending_count']?> Pending</span><small>Total <?=money((float)$r['total_emi'])?> · Paid <?=money((float)$r['paid_emi'])?></small></div></td><td data-label="Outstanding"><b><?=money($out)?></b></td><td data-label="Next Due"><?=h($r['next_due']?:'—')?></td></tr><?php endwhile; if(!$has): ?><tr><td colspan="6"><div class="empty-report">No loan data available yet.</div></td></tr><?php endif; else: ?><tr><td colspan="6"><div class="empty-report">No loan data available yet.</div></td></tr><?php endif; ?></tbody></table></div></div>
    <div class="ml-page report-member-directory">
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">📊</div>
          <div>
            <h1>Member-wise Report</h1>
            <p>Contribution, loan and EMI details</p>
          </div>
        </div>
        <a class="ml-btn-add report-download-btn" href="?route=member-excel">⬇ Download Excel</a>
      </div>
      <div class="report-list-note">सदस्यवार जमा, ऋण और EMI का पूरा विवरण · Members list के समान layout</div>
      <div class="ml-table-card report-member-table-card">
        <div class="table-wrap">
          <table class="ml-table report-member-ml-table">
            <thead>
              <tr>
                <th>#</th><th>Photo</th><th>Member ID</th><th>Name</th><th>Mobile</th>
                <th>Contribution</th><th>Loan Principal</th><th>EMI Total</th><th>EMI Paid</th><th>Outstanding</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
<?php $mr=$db->query("SELECT m.id,m.code,m.name,m.mobile,m.photo,m.status,m.gender,m.created_at,COALESCE((SELECT SUM(amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) contribution_total,COALESCE((SELECT SUM(principal) FROM loans l WHERE l.member_id=m.id),0) loan_principal,COALESCE((SELECT SUM(amount) FROM emi_schedule e JOIN loans l2 ON l2.id=e.loan_id WHERE l2.member_id=m.id),0) emi_total,COALESCE((SELECT SUM(paid_amount) FROM emi_schedule e JOIN loans l3 ON l3.id=e.loan_id WHERE l3.member_id=m.id),0) emi_paid,COALESCE((SELECT SUM(MAX(e.amount-e.paid_amount,0)) FROM emi_schedule e JOIN loans l4 ON l4.id=e.loan_id WHERE l4.member_id=m.id),0) emi_outstanding FROM members m ORDER BY m.name"); $memberNo=0; while($r=$mr->fetchArray(SQLITE3_ASSOC)): $memberNo++; $photoUrl=!empty($r['photo'])?memberFileUrl($r['photo']):''; $status=trim((string)($r['status']??'Active')); ?>
              <tr>
                <td data-label="#"><?= $memberNo ?></td>
                <td data-label="Photo"><?php if($photoUrl): ?><img class="ml-photo" src="<?=h($photoUrl)?>" alt=""><?php else: ?><div class="ml-photo placeholder">👤</div><?php endif; ?></td>
                <td data-label="Member ID"><span class="ml-code"><?=h($r['code'])?></span></td>
                <td data-label="Name"><b><?=h($r['name'])?></b></td>
                <td data-label="Mobile"><?=h($r['mobile']?:'—')?></td>
                <td data-label="Contribution"><b><?=money((float)$r['contribution_total'])?></b></td>
                <td data-label="Loan Principal"><?=money((float)$r['loan_principal'])?></td>
                <td data-label="EMI Total"><?=money((float)$r['emi_total'])?></td>
                <td data-label="EMI Paid"><?=money((float)$r['emi_paid'])?></td>
                <td data-label="Outstanding"><b><?=money((float)$r['emi_outstanding'])?></b></td>
                <td data-label="Status"><?php if($status==='Active'): ?><span class="ml-status active">✓ Active</span><?php elseif($status==='Closed'): ?><span class="ml-status closed">Closed</span><?php else: ?><span class="ml-status inactive">Inactive</span><?php endif; ?></td>
              </tr>
<?php endwhile; if($memberNo===0): ?><tr><td colspan="11" class="ml-empty">No member records available yet.</td></tr><?php endif; ?>
            </tbody>
          </table>
        </div>
        <div class="report-member-count">Showing <?=number_format($memberNo)?> member<?= $memberNo===1?'':'s' ?> · सभी सदस्य</div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Reports',$c); exit;
}

if($route==='interest-refund-settings'){
    requireLogin(); if(!isSuperAdmin()){http_response_code(403);exit('Super Admin only');}
    $msg=''; $msgType='success'; $preview=null;
    $defaultYear=date('Y',strtotime('-1 year'));
    $selectedYear=preg_match('/^\d{4}$/',(string)($_REQUEST['financial_year']??''))?(string)$_REQUEST['financial_year']:$defaultYear;
    $reservePercent=(float)getSetting('profit_reserve_percent','10'); $exitMethod=(string)getSetting('member_exit_interest_method','A');
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=(string)($_POST['action']??'');
        try{
            if($action==='save_settings'){
                $rp=(float)($_POST['reserve_percent']??10); if($rp<0||$rp>100)throw new RuntimeException('Reserve percent 0 से 100 के बीच होना चाहिए.');
                $method=(string)($_POST['exit_interest_method']??'A'); if(!in_array($method,['A','B'],true)) $method='A'; setSetting('profit_reserve_percent',(string)$rp); setSetting('profit_distribution_method','Equal among eligible active members'); setSetting('member_exit_interest_method',$method);
                setSetting('profit_legal_reference',trim((string)($_POST['legal_reference']??'')));
                audit('interest_refund_settings_saved','Reserve='.$rp.'%; legal reference updated');
                $db->exec("INSERT INTO financial_audit_logs(actor_id,action,entity_type,details) VALUES(".(int)user()['id'].",'Settings updated','settings',".$db->escapeString('Reserve='.$rp.'%; reference='.trim((string)($_POST['legal_reference']??''))).")");
                $msg='Interest & Refund settings सुरक्षित कर दी गईं.'; $reservePercent=$rp; $exitMethod=$method;
            }elseif($action==='add_income'){
                $amount=round((float)($_POST['amount']??0),2); $note=trim((string)($_POST['note']??'')); $dt=(string)($_POST['income_date']??date('Y-m-d'));
                if($amount<=0||!preg_match('/^\d{4}-\d{2}-\d{2}$/',$dt)||$note==='')throw new RuntimeException('Other income के लिए सही राशि, तारीख और विवरण भरें.');
                $st=$db->prepare('INSERT INTO financial_other_income(amount,note,income_date,created_by) VALUES(?,?,?,?)');$st->bindValue(1,$amount,SQLITE3_FLOAT);$st->bindValue(2,$note,SQLITE3_TEXT);$st->bindValue(3,$dt,SQLITE3_TEXT);$st->bindValue(4,(int)user()['id'],SQLITE3_INTEGER);$st->execute();
                $msg='Other income दर्ज हो गई.';
            }elseif($action==='preview'){
                $selectedYear=(string)($_POST['financial_year']??$selectedYear); if(!preg_match('/^\d{4}$/',$selectedYear))throw new RuntimeException('सही financial year चुनें.');
                $existing=$db->prepare('SELECT status FROM financial_year_closings WHERE financial_year=?');$existing->bindValue(1,$selectedYear);$er=$existing->execute()->fetchArray(SQLITE3_ASSOC);if($er && $er['status']!=='Draft')throw new RuntimeException('इस financial year की closing पहले से approved/locked है.');
                $start=$selectedYear.'-01-01';$end=((int)$selectedYear+1).'-01-01';
                $q=$db->prepare("SELECT COALESCE(SUM(interest_amount),0) FROM interest_collections WHERE created_at>=? AND created_at<?");$q->bindValue(1,$start);$q->bindValue(2,$end);$interest=(float)$q->execute()->fetchArray(SQLITE3_NUM)[0];
                $q=$db->prepare('SELECT COALESCE(SUM(amount),0) FROM financial_other_income WHERE income_date>=? AND income_date<?');$q->bindValue(1,$start);$q->bindValue(2,$end);$other=(float)$q->execute()->fetchArray(SQLITE3_NUM)[0];
                $q=$db->prepare("SELECT COALESCE(SUM(amount),0) FROM fund_adjustments WHERE type='Expense' AND created_at>=? AND created_at<?");$q->bindValue(1,$start);$q->bindValue(2,$end);$expenses=(float)$q->execute()->fetchArray(SQLITE3_NUM)[0];
                $net=round($interest+$other-$expenses,2);$rp=(float)getSetting('profit_reserve_percent','10');$reserve=$net>0?round($net*$rp/100,2):0.0;$dist=max(0,round($net-$reserve,2));$eligible=(int)$db->querySingle("SELECT COUNT(*) FROM members WHERE status='Active'");$per=$eligible>0?round($dist/$eligible,2):0;
                $preview=['year'=>$selectedYear,'interest'=>$interest,'other'=>$other,'expenses'=>$expenses,'net'=>$net,'reserve'=>$reserve,'distributable'=>$dist,'eligible'=>$eligible,'per'=>$per,'rp'=>$rp];
                $_SESSION['financial_preview']=$preview; $msg='Preview तैयार है। यह अभी payment या closing नहीं करता.'; $msgType='info';
            }elseif($action==='approve_closing'){
                $pv=$_SESSION['financial_preview']??null; if(!$pv || (string)$pv['year']!==(string)($_POST['financial_year']??''))throw new RuntimeException('पहले इसी financial year का preview दोबारा बनाएं.');
                if((float)$pv['net']<=0)throw new RuntimeException('Net profit शून्य/नकारात्मक है; benefit distribution approve नहीं हो सकता.');
                if((int)$pv['eligible']<1)throw new RuntimeException('कोई eligible Active member नहीं है.');
                $db->exec('BEGIN IMMEDIATE');
                $q=$db->prepare('SELECT id,status FROM financial_year_closings WHERE financial_year=?');$q->bindValue(1,$pv['year']);$old=$q->execute()->fetchArray(SQLITE3_ASSOC);if($old && $old['status']!=='Draft')throw new RuntimeException('Financial year already locked.');
                if($old){$cid=(int)$old['id'];$u=$db->prepare("UPDATE financial_year_closings SET interest_received=?,other_income=?,operating_expenses=?,net_profit=?,reserve_percent=?,reserve_amount=?,distributable_amount=?,eligible_members=?,per_member_amount=?,status='Approved',approved_by=?,approved_at=CURRENT_TIMESTAMP WHERE id=? AND status='Draft'");$idx=0;}else{$u=$db->prepare("INSERT INTO financial_year_closings(financial_year,interest_received,other_income,operating_expenses,net_profit,reserve_percent,reserve_amount,distributable_amount,eligible_members,per_member_amount,status,approved_by,approved_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,'Approved',?,CURRENT_TIMESTAMP,?)");$idx=0;$u->bindValue(++$idx,$pv['year'],SQLITE3_TEXT);$cid=0;}
                foreach(['interest','other','expenses','net','rp','reserve','distributable','eligible','per'] as $k){$val=$pv[$k];$u->bindValue(++$idx,$val,is_int($val)?SQLITE3_INTEGER:SQLITE3_FLOAT);} $u->bindValue(++$idx,(int)user()['id'],SQLITE3_INTEGER);if($old)$u->bindValue(++$idx,$cid,SQLITE3_INTEGER);else $u->bindValue(++$idx,(int)user()['id'],SQLITE3_INTEGER);if(!$u->execute())throw new RuntimeException('Financial closing save failed.');if(!$old)$cid=(int)$db->lastInsertRowID();
                $db->exec('DELETE FROM member_dividend_allocations WHERE closing_id='.$cid.' AND status=\'Pending\'');
                $members=$db->query("SELECT id FROM members WHERE status='Active' ORDER BY id");$base=(int)floor(((float)$pv['distributable']*100)/max(1,(int)$pv['eligible']));$remaining=(int)round((float)$pv['distributable']*100)-$base*(int)$pv['eligible'];$n=0;
                while($m=$members->fetchArray(SQLITE3_ASSOC)){$cents=$base+($n<$remaining?1:0);$ins=$db->prepare("INSERT INTO member_dividend_allocations(closing_id,financial_year,member_id,amount,status) VALUES(?,?,?,?,'Pending')");$ins->bindValue(1,$cid,SQLITE3_INTEGER);$ins->bindValue(2,$pv['year'],SQLITE3_TEXT);$ins->bindValue(3,(int)$m['id'],SQLITE3_INTEGER);$ins->bindValue(4,$cents/100,SQLITE3_FLOAT);$ins->execute();$n++;}
                $db->exec("INSERT INTO financial_audit_logs(actor_id,action,entity_type,entity_id,details) VALUES(".(int)user()['id'].",'Financial year approved and locked','financial_year_closing',".$cid.",".$db->escapeString('year='.$pv['year'].'; net='.$pv['net'].'; reserve='.$pv['reserve'].'; distributable='.$pv['distributable']).")");$db->exec('COMMIT');unset($_SESSION['financial_preview']);$msg='Financial year approve/lock हो गया। अब member-wise allocation नीचे दिखेगा.';
            }elseif($action==='mark_paid'){
                $aid=(int)($_POST['allocation_id']??0);$ref=trim((string)($_POST['payment_reference']??''));if($ref==='')throw new RuntimeException('Payment transaction/reference number जरूरी है.');
                $db->exec('BEGIN IMMEDIATE');$q=$db->prepare("SELECT a.*,c.status closing_status FROM member_dividend_allocations a JOIN financial_year_closings c ON c.id=a.closing_id WHERE a.id=?");$q->bindValue(1,$aid,SQLITE3_INTEGER);$a=$q->execute()->fetchArray(SQLITE3_ASSOC);if(!$a||$a['status']!=='Pending'||$a['closing_status']!=='Approved')throw new RuntimeException('Allocation pending नहीं है या closing approved नहीं है.');
                $u=$db->prepare("UPDATE member_dividend_allocations SET status='Paid',payment_reference=?,paid_at=CURRENT_TIMESTAMP,paid_by=? WHERE id=? AND status='Pending'");$u->bindValue(1,$ref,SQLITE3_TEXT);$u->bindValue(2,(int)user()['id'],SQLITE3_INTEGER);$u->bindValue(3,$aid,SQLITE3_INTEGER);if(!$u->execute()||$db->changes()!==1)throw new RuntimeException('Payment status update नहीं हुआ. Duplicate payment reference भी हो सकता है.');
                $db->exec("INSERT INTO financial_audit_logs(actor_id,action,entity_type,entity_id,details) VALUES(".(int)user()['id'].",'Dividend marked paid','member_dividend_allocation',".$aid.",".$db->escapeString('reference='.$ref.'; amount='.$a['amount']).")");$db->exec('COMMIT');$msg='Payment reference के साथ payout record हो गया. वास्तविक transfer पहले bank/UPI पर confirm करें.';
            }
        }catch(Throwable $e){@$db->exec('ROLLBACK');$msg=$e->getMessage();$msgType='danger';}
    }
    $reservePercent=(float)getSetting('profit_reserve_percent','10');
    $closingQ=$db->prepare('SELECT * FROM financial_year_closings WHERE financial_year=?');$closingQ->bindValue(1,$selectedYear);$closing=$closingQ->execute()->fetchArray(SQLITE3_ASSOC)?:null;
    $allocRows=[];if($closing){$q=$db->prepare('SELECT a.*,m.code,m.name FROM member_dividend_allocations a JOIN members m ON m.id=a.member_id WHERE a.closing_id=? ORDER BY m.name');$q->bindValue(1,(int)$closing['id'],SQLITE3_INTEGER);$rr=$q->execute();while($r=$rr->fetchArray(SQLITE3_ASSOC))$allocRows[]=$r;}
    $incomeRows=$db->query('SELECT * FROM financial_other_income ORDER BY income_date DESC,id DESC LIMIT 20');
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">SUPER ADMIN · FINANCE CONTROL</div><h1>🧮 Interest & Refund Settings</h1><p>वास्तविक प्राप्त ब्याज, लाभ का रिज़र्व, बराबर वार्षिक लाभ-वितरण और payout audit.</p></div><a class="btn" href="?route=admin-panel">← Admin Panel</a></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="alert info">महत्वपूर्ण: 10% रिज़र्व आपकी प्रस्तावित नीति है, अपने-आप कानूनी नियम नहीं। लागू कानून/समिति के उपनियम, वैधानिक रिज़र्व, बकाया देनदारियाँ और स्वीकृत accounts जाँचकर ही लाभ बाँटें। Principal EMI repayment को income नहीं माना गया है; केवल दर्ज/प्राप्त ब्याज शामिल है।</div>
    <div class="panel"><h2>⚙️ Distribution Policy</h2><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save_settings"><div><label>Net Profit Reserve (%)</label><input type="number" name="reserve_percent" min="0" max="100" step="0.01" required value="<?=h((string)$reservePercent)?>"></div><div><label>Annual Distribution Method</label><input value="Equal among eligible Active members" disabled><small>वार्षिक लाभ पात्र Active सदस्यों में बराबर बँटेगा।</small></div><div class="span2"><label>Member Close / Refund Interest Calculation</label><select name="exit_interest_method"><option value="A" <?=($exitMethod==='A'?'selected':'')?>>A — कुल जमा राशि के अनुपात में</option><option value="B" <?=($exitMethod==='B'?'selected':'')?>>B — जमा राशि × समिति में रहने के महीने</option></select><div class="alert info" style="margin-top:8px"><b>A का मतलब:</b> सदस्य का कुल जमा ÷ सभी Active सदस्यों की कुल जमा × उपलब्ध लोन-ब्याज पूल।<br><b>B का मतलब:</b> हर जमा राशि को समिति में रहने वाले महीनों से गुणा करके अनुपात निकलेगा; जितने अधिक महीने पैसा जमा रहा, उतना अधिक वेटेज।<br>दोनों तरीकों में केवल वास्तव में वसूला गया लोन ब्याज लिया जाएगा; रिज़र्व/पहले से स्वीकृत ब्याज रिफंड घटाने के बाद हिस्सा निकलेगा।</div></div><div class="span2"><label>Bylaws / Legal Approval Reference</label><input name="legal_reference" value="<?=h(getSetting('profit_legal_reference',''))?>" placeholder="Resolution number, bylaws clause, approval reference"></div><div class="span2"><button class="btn primary">Save Policy</button></div></form></div>
    <div class="panel"><h2>➕ Other Verified Income</h2><p class="muted">केवल वास्तविक, दस्तावेज़ से सत्यापित income दर्ज करें। Loan principal repayment या member contribution यहाँ न जोड़ें।</p><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="add_income"><div><label>Amount (₹)</label><input name="amount" type="number" step="0.01" min="0.01" required></div><div><label>Income Date</label><input name="income_date" type="date" value="<?=date('Y-m-d')?>" required></div><div class="span2"><label>Description / Evidence Reference</label><input name="note" required></div><div class="span2"><button class="btn">Add Income Entry</button></div></form></div>
    <div class="panel"><h2>📅 Annual Profit Calculation</h2><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="preview"><div><label>Calendar Financial Year</label><input type="number" name="financial_year" min="2000" max="2100" value="<?=h($selectedYear)?>" required></div><div class="span2"><button class="btn primary">Calculate Preview</button></div></form>
    <?php if(!empty($_SESSION['financial_preview']) && (string)$_SESSION['financial_preview']['year']===$selectedYear && !$closing): $pv=$_SESSION['financial_preview']; ?><div class="kpis"><div class="kpi teal"><span>Received Loan Interest</span><b><?=money((float)$pv['interest'])?></b></div><div class="kpi blue"><span>Other Income</span><b><?=money((float)$pv['other'])?></b></div><div class="kpi orange"><span>Operating Expenses</span><b><?=money((float)$pv['expenses'])?></b></div><div class="kpi purple"><span>Net Profit</span><b><?=money((float)$pv['net'])?></b></div><div class="kpi pink"><span>Reserve (<?=h((string)$pv['rp'])?>%)</span><b><?=money((float)$pv['reserve'])?></b></div><div class="kpi green"><span>Distributable</span><b><?=money((float)$pv['distributable'])?></b><small><?=number_format((int)$pv['eligible'])?> eligible · <?=money((float)$pv['per'])?> each approx.</small></div></div><form method="post" onsubmit="return confirm('Financial year को lock करके member-wise benefit allocations बनाएं? इसे approve करने से पहले income/expense records जाँच लें।')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="approve_closing"><input type="hidden" name="financial_year" value="<?=h($selectedYear)?>"><button class="btn primary" <?=((float)$pv['net']<=0||(int)$pv['eligible']<1)?'disabled':''?>>Approve & Lock Financial Year</button></form><?php endif; ?>
    <?php if($closing): ?><div class="alert success">Financial year <?=h($selectedYear)?> — <?=h($closing['status'])?>. यह closing locked है।</div><div class="kpis"><div class="kpi teal"><span>Received Interest</span><b><?=money((float)$closing['interest_received'])?></b></div><div class="kpi blue"><span>Other Income</span><b><?=money((float)$closing['other_income'])?></b></div><div class="kpi orange"><span>Expenses</span><b><?=money((float)$closing['operating_expenses'])?></b></div><div class="kpi purple"><span>Net Profit</span><b><?=money((float)$closing['net_profit'])?></b></div><div class="kpi pink"><span>Reserve</span><b><?=money((float)$closing['reserve_amount'])?></b></div><div class="kpi green"><span>Distributable</span><b><?=money((float)$closing['distributable_amount'])?></b><small><?=number_format((int)$closing['eligible_members'])?> eligible</small></div></div><?php endif; ?></div>
    <?php if($closing): ?><div class="panel"><div class="panel-head"><h2>Member-wise Benefit / Payout Register</h2><span class="badge info">Pending <?=count(array_filter($allocRows,fn($x)=>$x['status']==='Pending'))?> · Paid <?=count(array_filter($allocRows,fn($x)=>$x['status']==='Paid'))?></span></div><div class="table-wrap"><table><thead><tr><th>Member</th><th>Benefit</th><th>Status</th><th>Payment Reference / Action</th></tr></thead><tbody><?php foreach($allocRows as $a): ?><tr><td><b><?=h($a['name'])?></b><small class="block"><?=h($a['code'])?></small></td><td><?=money((float)$a['amount'])?></td><td><?=h($a['status'])?></td><td><?php if($a['status']==='Pending'): ?><form method="post" class="inline-form" onsubmit="return confirm('Bank/UPI transfer पूरा होने की पुष्टि करते हैं?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="mark_paid"><input type="hidden" name="allocation_id" value="<?=$a['id']?>"><input name="payment_reference" required placeholder="Unique UPI/bank ref" style="max-width:190px"><button class="btn small primary">Mark Paid</button></form><?php else: ?><small><?=h($a['payment_reference'])?> · <?=h($a['paid_at'])?></small><?php endif; ?></td></tr><?php endforeach; if(!$allocRows): ?><tr><td colspan="4">No allocations.</td></tr><?php endif; ?></tbody></table></div></div><?php endif; ?>
    <div class="panel"><h2>Recent Other Income Entries</h2><div class="table-wrap"><table><thead><tr><th>Date</th><th>Amount</th><th>Description / Evidence</th></tr></thead><tbody><?php $any=false;while($ir=$incomeRows->fetchArray(SQLITE3_ASSOC)){$any=true; ?><tr><td><?=h($ir['income_date'])?></td><td><?=money((float)$ir['amount'])?></td><td><?=h($ir['note'])?></td></tr><?php }if(!$any): ?><tr><td colspan="3">No other income recorded.</td></tr><?php endif; ?></tbody></table></div></div>
    <div class="panel"><h2>Member Exit Refund</h2><p>Member Exit / Refund का मौजूदा workflow <a href="?route=member-close">Member Closure</a> में रहेगा। रिफंड राशि approve करने से पहले paid contribution principal, unpaid/approved benefit, outstanding loan और केवल वैध/स्वीकृत deductions मिलाएँ। यह annual benefit से अलग है; यहाँ annual allocation को अपने-आप exit refund में नहीं जोड़ा गया है।</p><p class="muted">सभी भुगतान पहले वास्तविक bank/UPI पर verify करें। यह screen payment transfer नहीं करती, केवल approved reference record करती है।</p></div>
    <?php $c=ob_get_clean(); layout('Interest & Refund Settings',$c); exit;
}

if($route==='fund-adjustments'){
    requireRole(['admin']); $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){ checkCsrf(); $type=$_POST['type']??'Expense'; $amount=(float)($_POST['amount']??0); $note=trim((string)($_POST['note']??'')); if(!in_array($type,['Expense','Withdrawal'],true)||$amount<=0){$msg='Enter a valid amount and type.';$msgType='danger';}else{$st=$db->prepare('INSERT INTO fund_adjustments(type,amount,note,created_by) VALUES(?,?,?,?)');$st->bindValue(1,$type);$st->bindValue(2,$amount);$st->bindValue(3,$note);$st->bindValue(4,(int)user()['id']);$st->execute();$msg='Fund adjustment added.';}}
    $total=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM fund_adjustments"); $rows=$db->query("SELECT f.*,u.username FROM fund_adjustments f LEFT JOIN users u ON u.id=f.created_by ORDER BY f.id DESC");
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ADMIN FUND</div><h1>Expenses & Withdrawals</h1><p>Available fund deductions. <span class="hi-sub">खर्च और निकासी उपलब्ध फंड से घटेगी।</span></p></div></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="panel"><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><div><label>Type</label><select name="type"><option>Expense</option><option>Withdrawal</option></select></div><div><label>Amount (₹)</label><input name="amount" type="number" step="0.01" min="0.01" required></div><div class="span2"><label>Note</label><input name="note" placeholder="Reason / description"></div><div class="span2"><button class="btn primary">＋ Add Deduction</button><span class="badge warning" style="margin-left:8px">Total deductions <?=money($total)?></span></div></form></div><div class="panel"><div class="panel-head"><h2>Adjustment History</h2></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Type</th><th>Amount</th><th>Note</th><th>By</th></tr></thead><tbody><?php $has=false; while($r=$rows->fetchArray(SQLITE3_ASSOC)){$has=true; ?><tr><td><?=h($r['created_at'])?></td><td><span class="badge warning"><?=h($r['type'])?></span></td><td><?=money((float)$r['amount'])?></td><td><?=h($r['note']?:'—')?></td><td><?=h($r['username']??'—')?></td></tr><?php } if(!$has): ?><tr><td colspan="5">No expenses or withdrawals recorded.</td></tr><?php endif; ?></tbody></table></div></div><?php $c=ob_get_clean(); layout('Expenses & Withdrawals',$c); exit;
}

if($route==='settings'){
    requireRole(['admin']);$msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        try {
            foreach(['monthly_contribution','loan_eligibility_percent','upi_id','upi_name','payment_api_url','payment_api_key','payment_api_secret','loan_payout_provider','loan_payout_mode','loan_payout_api_url','loan_payout_api_key','loan_payout_api_secret','loan_payout_account_id','loan_payout_webhook_secret','loan_payout_enabled','society_name','society_tagline','notice_text','notice_enabled'] as $k){$v=trim($_POST[$k]??'');$st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");$st->bindValue(1,$k);$st->bindValue(2,$v);$st->execute();}
            if(isset($_FILES['header_logo']) && ($_FILES['header_logo']['error'] ?? UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE){
                $newLogo=uploadBrandLogo('header_logo'); $oldLogo=getSetting('header_logo','assets/logo.png');
                $st=$db->prepare("INSERT INTO settings(key,value) VALUES('header_logo',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$newLogo,SQLITE3_TEXT); $st->execute();
                if(str_starts_with($oldLogo,'uploads/branding/')){ $oldPath=__DIR__.'/'.ltrim($oldLogo,'/'); if(is_file($oldPath)) @unlink($oldPath); }
                $msg='Settings and header branding saved successfully.';
            } else { $msg='Settings saved successfully.'; }
        } catch(Throwable $e) { $msg=$e->getMessage(); $msgType='danger'; }
    }
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ADMIN CONTROL</div><h1>Settings</h1><p>Configure monthly contribution, loan eligibility and UPI details. <span class="hi-sub">मासिक जमा, ऋण सीमा और UPI विवरण सेट करें।</span></p></div><a class="btn" href="?route=communications">💬 WhatsApp & SMS</a></div><?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?><div class="panel"><form method="post" enctype="multipart/form-data" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><div class="span2 branding-settings"><div><label>Header / Sidebar Name</label><input name="society_name" value="<?=h(getSetting('society_name'))?>" placeholder="GS Suraha Sahyog Samiti"></div><div><label>Header Tagline</label><input name="society_tagline" value="<?=h(getSetting('society_tagline'))?>" placeholder="Finance Co-operative Society"></div><div><label>Header / Sidebar Logo</label><input name="header_logo" type="hidden" value="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>"><input name="header_logo" type="file" accept="image/png,image/jpeg,image/webp"><small class="muted">PNG/JPG/WebP, max 3 MB. New logo will replace the current header/sidebar logo.</small></div><div class="branding-preview"><img src="<?=h(brandingAssetSetting('header_logo','assets/logo.png'))?>" alt="Current header logo"><small>Current logo</small></div></div><div><label>Monthly Fixed Contribution (₹)</label><input name="monthly_contribution" value="<?=h(getSetting('monthly_contribution'))?>" type="number" step="0.01"></div><div><label>Maximum Loan Against Deposit (%)</label><input name="loan_eligibility_percent" value="<?=h(getSetting('loan_eligibility_percent'))?>" type="number" step="0.01" min="0" max="100"></div><div><label>UPI ID / Merchant VPA</label><input name="upi_id" value="<?=h(getSetting('upi_id'))?>" placeholder="example@upi"></div><div><label>UPI Display Name</label><input name="upi_name" value="<?=h(getSetting('upi_name'))?>"></div><div><label>Payment API URL</label><input name="payment_api_url" value="<?=h(getSetting('payment_api_url'))?>" placeholder="Gateway checkout/API endpoint"></div><div><label>Payment API Key</label><input name="payment_api_key" type="password" value="<?=h(getSetting('payment_api_key'))?>" placeholder="Keep secret"></div><div><label>Payment API Secret / Signature</label><input name="payment_api_secret" type="password" value="<?=h(getSetting('payment_api_secret'))?>" placeholder="For gateway callback verification"></div><div class="span2"><div class="panel" style="margin:8px 0 0;padding:16px"><h2>🏦 Loan Transfer API / ऋण ट्रांसफर API</h2><p class="muted">अभी form/configuration तैयार है। API Key बाद में जोड़कर Bank + UPI payout चालू किया जा सकता है।</p><div class="settings-grid"><div><label>Payout Provider</label><input name="loan_payout_provider" value="<?=h(getSetting('loan_payout_provider'))?>" placeholder="RazorpayX / Cashfree / Other"></div><div><label>Transfer Mode</label><select name="loan_payout_mode"><option <?=getSetting('loan_payout_mode','Disabled until API credentials are added')==='Disabled until API credentials are added'?'selected':''?>>Disabled until API credentials are added</option><option <?=getSetting('loan_payout_mode')==='Bank + UPI'?'selected':''?>>Bank + UPI</option><option <?=getSetting('loan_payout_mode')==='Bank only'?'selected':''?>>Bank only</option><option <?=getSetting('loan_payout_mode')==='UPI only'?'selected':''?>>UPI only</option></select></div><div><label>Payout API URL</label><input name="loan_payout_api_url" value="<?=h(getSetting('loan_payout_api_url'))?>" placeholder="https://api.provider.com/..."></div><div><label>API Key / Client ID</label><input name="loan_payout_api_key" type="password" value="<?=h(getSetting('loan_payout_api_key'))?>" placeholder="बाद में जोड़ें"></div><div><label>API Secret</label><input name="loan_payout_api_secret" type="password" value="<?=h(getSetting('loan_payout_api_secret'))?>" placeholder="बाद में जोड़ें"></div><div><label>Merchant / Account ID</label><input name="loan_payout_account_id" value="<?=h(getSetting('loan_payout_account_id'))?>" placeholder="Provider account ID"></div><div><label>Webhook Secret</label><input name="loan_payout_webhook_secret" type="password" value="<?=h(getSetting('loan_payout_webhook_secret'))?>" placeholder="Optional"></div><div><label>API Transfer</label><select name="loan_payout_enabled"><option value="0" <?=getSetting('loan_payout_enabled','0')==='0'?'selected':''?>>Disabled / बंद</option><option value="1" <?=getSetting('loan_payout_enabled')==='1'?'selected':''?>>Enabled / चालू</option></select></div></div><div class="alert info" style="margin-top:12px">Credentials खाली रहने पर कोई वास्तविक पैसा transfer नहीं होगा।</div></div></div><div class="span2"><label>Dashboard Text Notice</label><textarea name="notice_text" rows="3" placeholder="Write an announcement for members and staff..."><?=h(getSetting('notice_text'))?></textarea></div><div><label>Notice</label><select name="notice_enabled"><option value="1" <?=getSetting('notice_enabled','1')==='1'?'selected':''?>>Show</option><option value="0" <?=getSetting('notice_enabled','1')==='0'?'selected':''?>>Hide</option></select></div><div class="span2"><button class="btn primary">Save Settings</button></div></form><div class="panel" style="margin-top:16px"><div class="panel-head"><div><h2>📢 Notice Management</h2><small class="muted">Notice add, edit, hide/show और delete करें।</small></div><form method="post" action="?route=notice-action&amp;return=settings" onsubmit="return confirm('Dashboard का Notice Text delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="clear_static_notice"><button class="btn small danger">🗑️ Delete Notice Text</button></form></div><div class="table-wrap"><table><thead><tr><th>Notice</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody><?php $nq=$db->query("SELECT * FROM notices ORDER BY id DESC LIMIT 50"); $nh=false; while($nr=$nq->fetchArray(SQLITE3_ASSOC)){$nh=true; ?><tr><td><b><?=h($nr['title']?:'Notice')?></b><small class="block"><?=nl2br(h($nr['body']))?></small></td><td><?=((int)$nr['enabled']===1?'Active':'Hidden')?></td><td><?=h($nr['created_at'])?></td><td><form method="post" action="?route=notice-action&amp;return=settings" style="display:grid;gap:5px;min-width:230px"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="edit_notice"><input type="hidden" name="id" value="<?=$nr['id']?>"><input name="title" value="<?=h($nr['title'])?>"><textarea name="body" rows="2"><?=h($nr['body'])?></textarea><button class="btn small">Save</button></form><div class="inline-form" style="margin-top:5px"><form method="post" action="?route=notice-action&amp;return=settings" onsubmit="return confirm('Notice delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete_notice"><input type="hidden" name="id" value="<?=$nr['id']?>"><button class="btn small danger">Delete</button></form><form method="post" action="?route=notice-action&amp;return=settings"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="toggle_notice"><input type="hidden" name="id" value="<?=$nr['id']?>"><button class="btn small"><?=((int)$nr['enabled']===1?'Hide':'Show')?></button></form></div></td></tr><?php } if(!$nh): ?><tr><td colspan="4">No notices added.</td></tr><?php endif; ?></tbody></table></div></div><div class="alert info">Online QR payments are recorded as Pending until your authorized staff/admin verifies the transaction. Connect a real merchant gateway for automatic server-side verification.</div></div><?php $c=ob_get_clean(); layout('Settings',$c); exit;
}

if($route==='admin-users'){
    requireLogin(); if(!isSuperAdmin()) { http_response_code(403); exit('Super Admin only'); }
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $action=$_POST['action']??'';
        try {
            if($action==='save'){
                $id=(int)($_POST['id']??0);
                $username=trim($_POST['username']??'');
                $display=trim($_POST['display_name']??'');
                $password=(string)($_POST['password']??'');
                $caps=array_values(array_unique(array_filter((array)($_POST['caps']??[]), fn($x)=>in_array($x,['dashboard','members','contributions','loans','payments','reports','reminders','settings','communications','whatsapp-center','whatsapp-sms-center','admins','funds','backup','notifications','users'],true))));
                if($username==='') throw new RuntimeException('Admin ID is required.');
                if(!preg_match('/^[A-Za-z0-9._-]{3,40}$/',$username)) throw new RuntimeException('Admin ID can contain letters, numbers, dot, underscore and hyphen only.');
                if($id>0){
                    $old=$db->prepare("SELECT * FROM users WHERE id=? AND role='admin'"); $old->bindValue(1,$id); $row=$old->execute()->fetchArray(SQLITE3_ASSOC);
                    if(!$row) throw new RuntimeException('Admin account not found.');
                    if($password!==''){
                        if(strlen($password)<8) throw new RuntimeException('Password must be at least 8 characters.');
                        $st=$db->prepare("UPDATE users SET username=?,display_name=?,password_hash=? WHERE id=? AND role='admin'");
                        $st->bindValue(3,password_hash($password,PASSWORD_DEFAULT),SQLITE3_TEXT);
                    } else {
                        $st=$db->prepare("UPDATE users SET username=?,display_name=? WHERE id=? AND role='admin'");
                    }
                    $st->bindValue(1,$username,SQLITE3_TEXT); $st->bindValue(2,$display,SQLITE3_TEXT);
                    $st->bindValue($password!==''?4:3,$id,SQLITE3_INTEGER); $st->execute();
                    $db->exec('DELETE FROM admin_permissions WHERE user_id='.(int)$id);
                    foreach($caps as $cap){ $ps=$db->prepare('INSERT OR IGNORE INTO admin_permissions(user_id,capability) VALUES(?,?)'); $ps->bindValue(1,$id,SQLITE3_INTEGER); $ps->bindValue(2,$cap,SQLITE3_TEXT); $ps->execute(); }
                    audit('admin_updated','Admin ID #'.$id.' permissions updated');
                    if((int)user()['id']===$id){
                        $_SESSION['user']['username']=$username; $_SESSION['user']['display_name']=$display;
                    }
                    $msg='Admin ID updated successfully.';
                } else {
                    if(strlen($password)<8) throw new RuntimeException('Password must be at least 8 characters.');
                    $st=$db->prepare("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)");
                    $st->bindValue(1,$username,SQLITE3_TEXT); $st->bindValue(2,password_hash($password,PASSWORD_DEFAULT),SQLITE3_TEXT); $st->bindValue(3,'admin',SQLITE3_TEXT); $st->bindValue(4,$display ?: 'Administrator',SQLITE3_TEXT); $st->execute();
                    $newId=(int)$db->lastInsertRowID(); foreach($caps as $cap){ $ps=$db->prepare('INSERT OR IGNORE INTO admin_permissions(user_id,capability) VALUES(?,?)'); $ps->bindValue(1,$newId,SQLITE3_INTEGER); $ps->bindValue(2,$cap,SQLITE3_TEXT); $ps->execute(); } audit('admin_created','Admin ID #'.$newId.' created');
                    $msg='New Admin ID created successfully.';
                }
            } elseif($action==='delete'){
                $id=(int)($_POST['id']??0);
                if($id===(int)user()['id']) throw new RuntimeException('You cannot delete the currently logged-in Admin ID.');
                $total=(int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role='admin'");
                if($total<=1) throw new RuntimeException('At least one Admin ID must remain.');
                $st=$db->prepare("DELETE FROM users WHERE id=? AND role='admin'"); $st->bindValue(1,$id,SQLITE3_INTEGER); $st->execute(); audit('admin_deleted','Admin ID #'.$id.' deleted');
                $msg='Admin ID deleted.';
            }
        } catch(Throwable $e) { $msg=$e->getMessage(); $msgType='danger'; }
    }
    $editId=(int)($_GET['edit']??0); $edit=null;
    if($editId){ $st=$db->prepare("SELECT id,username,display_name,created_at,is_super_admin FROM users WHERE id=? AND role='admin'"); $st->bindValue(1,$editId); $edit=$st->execute()->fetchArray(SQLITE3_ASSOC) ?: null; if($edit){ $pr=$db->prepare('SELECT capability FROM admin_permissions WHERE user_id=?'); $pr->bindValue(1,$editId,SQLITE3_INTEGER); $edit['caps']=[]; $rr=$pr->execute(); while($pp=$rr->fetchArray(SQLITE3_ASSOC)) $edit['caps'][]=$pp['capability']; } }
    $admins=$db->query("SELECT id,username,display_name,created_at FROM users WHERE role='admin' ORDER BY id ASC");
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">ADMIN CONTROL</div><h1>Admin IDs</h1><p>Create and manage Admin login IDs, names and passwords. <span class="hi-sub">एडमिन लॉगिन आईडी, नाम और पासवर्ड यहाँ बदलें।</span></p></div></div>
    <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2><?= $edit ? 'Edit Admin ID' : 'Create Admin ID' ?></h2><span class="badge success">Admin Only</span></div>
        <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save"><input type="hidden" name="id" value="<?=h((string)($edit['id']??0))?>">
          <div><label>Admin ID / Username</label><input name="username" value="<?=h($edit['username']??'')?>" required></div>
          <div><label>Display Name</label><input name="display_name" value="<?=h($edit['display_name']??'Administrator')?>" required></div>
          <div class="span2"><label>Password <?= $edit ? '(leave blank to keep current)' : '' ?></label><div class="password-field-wrap"><input name="password" type="password" minlength="8" <?= $edit ? '' : 'required' ?> placeholder="Minimum 8 characters"><button type="button" class="btn small" onclick="togglePasswordVisibility(this)">Show</button></div><small class="muted">Existing passwords are securely hashed; enter a new password here to reset it.</small></div>
          <div class="span2"><label>Permissions / अधिकार</label><div class="settings-grid" style="grid-template-columns:repeat(3,minmax(0,1fr));gap:8px"><?php $capLabels=['dashboard'=>'Dashboard','members'=>'Members','contributions'=>'Contributions','loans'=>'Loans','payments'=>'Payments','reports'=>'Reports','reminders'=>'Reminders','settings'=>'Settings','communications'=>'WhatsApp / SMS Settings','whatsapp-center'=>'WhatsApp Center','whatsapp-sms-center'=>'WhatsApp Settings','admins'=>'Admin IDs','funds'=>'Expenses / Withdrawals','backup'=>'Backup','notifications'=>'Notifications','users'=>'Staff / Member IDs']; foreach($capLabels as $ck=>$cl): ?><label style="display:flex;align-items:center;gap:7px;font-weight:500"><input type="checkbox" name="caps[]" value="<?=h($ck)?>" <?=in_array($ck,$edit['caps']??[],true)?'checked':''?>> <?=h($cl)?></label><?php endforeach; ?></div><small class="muted">Super Admin सभी permissions रखता है। दूसरे Admin को केवल यहाँ चुने गए controls मिलेंगे। <b>WhatsApp Center</b> में Bulk, Payment Slip और Chat Logs रहेंगे; <b>WhatsApp Settings</b> में Meta Connection, SMS Settings और Calling Logs रहेंगे।</small></div>
          <div class="span2"><button class="btn primary"><?= $edit ? 'Update Admin ID' : 'Create Admin ID' ?></button><?php if($edit): ?> <a class="btn" href="?route=admin-users">Cancel</a><?php endif; ?></div>
        </form>
      </div>
      <div class="panel"><div class="panel-head"><h2>Admin Accounts</h2><span class="badge info">Secure</span></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Admin ID</th><th>Access</th><th>Created</th><th>Action</th></tr></thead><tbody>
      <?php while($a=$admins->fetchArray(SQLITE3_ASSOC)): ?><tr><td><b><?=h($a['display_name']?:'Administrator')?></b></td><td><?=h($a['username'])?></td><td><?= (int)$a['is_super_admin']===1 ? '<span class="badge success">SUPER ADMIN</span>' : '<span class="badge info">LIMITED</span>' ?></td><td><?=h($a['created_at'])?></td><td><div class="inline-form"><a class="btn small" href="?route=admin-users&edit=<?=$a['id']?>">Edit</a><?php if((int)$a['id']!==(int)user()['id']): ?><form method="post" onsubmit="return confirm('Delete this Admin ID?');"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?=$a['id']?>"><button class="btn small danger">Delete</button></form><?php endif; ?></div></td></tr><?php endwhile; ?>
      </tbody></table></div><div class="alert info">Password is stored securely as a one-way hash. Never share an Admin password in chat or public code.</div></div>
    </div>
    <?php $c=ob_get_clean(); layout('Admin IDs',$c); exit;
}

if($route==='staff-member-assignment'){
    requireRole(['admin']);
    $msg=''; $msgType='success';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        try {
            $staffId=(int)($_POST['staff_id']??0);
            $check=$db->prepare("SELECT id FROM users WHERE id=? AND role='staff'"); $check->bindValue(1,$staffId,SQLITE3_INTEGER);
            if(!$check->execute()->fetchArray(SQLITE3_ASSOC)) throw new RuntimeException('Valid Staff select karein.');
            $db->exec('BEGIN IMMEDIATE');
            $del=$db->prepare('DELETE FROM staff_member_assignments WHERE staff_id=?'); $del->bindValue(1,$staffId,SQLITE3_INTEGER); $del->execute();
            $ids=array_unique(array_map('intval',$_POST['member_ids']??[]));
            $ins=$db->prepare('INSERT OR IGNORE INTO staff_member_assignments(staff_id,member_id,assigned_by) SELECT ?,id,? FROM members WHERE id=?');
            foreach($ids as $mid){ if($mid>0){$ins->bindValue(1,$staffId,SQLITE3_INTEGER);$ins->bindValue(2,(int)user()['id'],SQLITE3_INTEGER);$ins->bindValue(3,$mid,SQLITE3_INTEGER);$ins->execute();} }
            $db->exec('COMMIT'); $msg='Staff ke Members assignment save ho gaye.';
        } catch(Throwable $e){ @$db->exec('ROLLBACK'); $msg=$e->getMessage(); $msgType='danger'; }
    }
    $staffRows=[]; $r=$db->query("SELECT id,username,display_name FROM users WHERE role='staff' ORDER BY display_name,username"); while($x=$r->fetchArray(SQLITE3_ASSOC))$staffRows[]=$x;
    $memberRows=[]; $r=$db->query("SELECT id,code,name,mobile,status FROM members ORDER BY name"); while($x=$r->fetchArray(SQLITE3_ASSOC))$memberRows[]=$x;
    $selected=(int)($_GET['staff_id']??($_POST['staff_id']??($staffRows[0]['id']??0))); $assigned=[]; $st=$db->prepare('SELECT member_id FROM staff_member_assignments WHERE staff_id=?');$st->bindValue(1,$selected,SQLITE3_INTEGER);$rr=$st->execute();while($x=$rr->fetchArray(SQLITE3_ASSOC))$assigned[(int)$x['member_id']]=true;
    $obAssigned=[]; $q=$db->prepare("SELECT m.id,m.code,m.name,m.mobile,u.display_name staff_name,u.username staff_login FROM staff_member_assignments a JOIN members m ON m.id=a.member_id JOIN users u ON u.id=a.staff_id WHERE a.staff_id=? ORDER BY m.name");$q->bindValue(1,$selected,SQLITE3_INTEGER);$r=$q->execute();while($x=$r->fetchArray(SQLITE3_ASSOC))$obAssigned[]=$x;
    ob_start(); ?>
    <div class="ml-page">
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">🧑‍🤝‍🧑</div>
          <div>
            <h1>Staff–Member Mapping</h1>
            <p>Staff को Members assign करें · एक Member कई Staff से भी जुड़ सकता है</p>
          </div>
        </div>
        <a class="ml-btn-add" href="?route=member-balances">Available Balance →</a>
      </div>
      <?php if($msg): ?><div class="alert <?=h($msgType)?>"><?=h($msg)?></div><?php endif; ?>

      <form class="ml-filters sma-filters" method="get" action="">
        <input type="hidden" name="route" value="staff-member-assignment">
        <div class="sma-staff-row">
          <label class="sma-label">Staff</label>
          <select name="staff_id" onchange="this.form.submit()" class="sma-select">
            <?php foreach($staffRows as $sr): ?>
              <option value="<?=$sr['id']?>" <?=$selected===(int)$sr['id']?'selected':''?>><?=h(($sr['display_name']?:$sr['username']).' ('.$sr['username'].')')?></option>
            <?php endforeach; ?>
          </select>
          <span class="sma-hint">बदलें → list update</span>
        </div>
      </form>

      <?php if(!$staffRows): ?>
        <div class="alert info">पहले Staff & Member IDs में Staff account बनाइए।</div>
      <?php elseif($selected): ?>
      <form method="post">
        <input type="hidden" name="csrf" value="<?=h(csrf())?>">
        <input type="hidden" name="staff_id" value="<?=$selected?>">
        <div class="ml-table-card" style="margin-bottom:16px">
          <div class="ml-footer" style="border-bottom:1px solid #eef2f7;border-top:0">
            <span><b>Members assign करें</b> · <?=count($assigned)?> selected</span>
            <button class="ml-btn-search" type="submit" style="height:36px">Save Mapping</button>
          </div>
          <div class="table-wrap">
            <table class="ml-table gs-data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Assign</th>
                  <th>Member ID</th>
                  <th>Name</th>
                  <th>Mobile</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <?php $i=1; foreach($memberRows as $mr):
                  $st=trim((string)($mr['status']??'Active'));
                ?>
                <tr>
                  <td><?=$i++?></td>
                  <td><input type="checkbox" name="member_ids[]" value="<?=$mr['id']?>" <?=isset($assigned[(int)$mr['id']])?'checked':''?>></td>
                  <td><span class="ml-code"><?=h($mr['code'])?></span></td>
                  <td><b><?=h($mr['name'])?></b></td>
                  <td><?=h($mr['mobile'])?></td>
                  <td>
                    <?php if($st==='Active'): ?><span class="ml-status active">✓ Active</span>
                    <?php elseif($st==='Closed'): ?><span class="ml-status closed">Closed</span>
                    <?php else: ?><span class="ml-status inactive"><?=h($st)?></span><?php endif; ?>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </form>
      <?php endif; ?>

      <div class="ml-table-card">
        <div class="ml-footer" style="border-bottom:1px solid #eef2f7;border-top:0">
          <span><b>Assigned Members</b> · selected staff</span>
        </div>
        <div class="table-wrap">
          <table class="ml-table gs-data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Staff</th>
                <th>Member ID</th>
                <th>Member Name</th>
                <th>Mobile</th>
              </tr>
            </thead>
            <tbody>
              <?php if(!$obAssigned): ?>
                <tr><td colspan="5" class="ml-empty">Is Staff ko abhi koi Member assign nahi hai.</td></tr>
              <?php else: $j=1; foreach($obAssigned as $ar): ?>
                <tr>
                  <td><?=$j++?></td>
                  <td><?=h(($ar['staff_name']?:$ar['staff_login']).' ('.$ar['staff_login'].')')?></td>
                  <td><span class="ml-code"><?=h($ar['code'])?></span></td>
                  <td><b><?=h($ar['name'])?></b></td>
                  <td><?=h($ar['mobile'])?></td>
                </tr>
              <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Staff–Member Mapping',$c); exit;
}

if($route==='member-balances'){
    requireRole(['admin','staff']);
    $where=''; $params=[]; $u=user();
    if(($u['role']??'')==='staff') { $where='WHERE EXISTS (SELECT 1 FROM staff_member_assignments a WHERE a.member_id=m.id AND a.staff_id='.(int)$u['id'].')'; }
    $sql="SELECT m.id,m.code,m.name,m.mobile,m.status,
      COALESCE((SELECT SUM(c.amount) FROM contributions c WHERE c.member_id=m.id AND c.status='Paid'),0) deposits,
      COALESCE((SELECT SUM(mc.member_interest) FROM member_closures mc WHERE mc.member_id=m.id AND mc.status='Approved'),0) closed_interest,
      COALESCE((SELECT SUM(mc.refund_amount) FROM member_closures mc WHERE mc.member_id=m.id AND mc.status='Approved'),0) refunds,
      COALESCE((SELECT SUM(MAX(e.amount-e.paid_amount,0)) FROM emi_schedule e JOIN loans l ON l.id=e.loan_id WHERE l.member_id=m.id AND l.status='Active'),0) loan_outstanding,
      (SELECT GROUP_CONCAT(COALESCE(NULLIF(u.display_name,''),u.username), ', ') FROM staff_member_assignments a JOIN users u ON u.id=a.staff_id WHERE a.member_id=m.id) staff_names
      FROM members m $where ORDER BY m.name";
    $rows=$db->query($sql); $data=[]; $totDeposits=0; $totInterest=0; $totRefunds=0; $totOutstanding=0; $totAvailable=0;
    while($r=$rows->fetchArray(SQLITE3_ASSOC)){
      $approvedContrib=(float)$r['deposits'];
      $interest=(float)$db->querySingle("SELECT COALESCE(SUM(amount),0) FROM member_interest_ledger WHERE member_id=".(int)$r['id']);
      $refunds=(float)$r['refunds']; $net=max(0,round($approvedContrib+$interest-$refunds,2));
      $r['interest']=$interest; $r['available']=$r['status']==='Closed'?0:$net; $data[]=$r;
      $totDeposits+=$approvedContrib;$totInterest+=$interest;$totRefunds+=$refunds;$totOutstanding+=(float)$r['loan_outstanding'];$totAvailable+=$r['available'];
    }
    $q=trim((string)($_GET['q']??'')); if($q!=='')$data=array_values(array_filter($data,fn($r)=>stripos($r['name'],$q)!==false||stripos($r['code'],$q)!==false||stripos($r['mobile'],$q)!==false));
    $rowCount=count($data);
    ob_start(); ?>
    <div class="ml-page mb-page">
      <div class="ml-header">
        <div class="ml-header-left">
          <div class="ml-header-icon">💳</div>
          <div>
            <h1>Member Available Balance</h1>
            <p>Paid Contribution + Interest − Refund · Loan outstanding अलग</p>
          </div>
        </div>
        <?php if(($u['role']??'')==='admin'): ?>
        <a class="ml-btn-add" href="?route=staff-member-assignment">Staff Mapping →</a>
        <?php endif; ?>
      </div>

      <form class="ml-filters" method="get" action="">
        <input type="hidden" name="route" value="member-balances">
        <div class="ml-search-wrap">
          <span class="ml-search-icon">🔍</span>
          <input type="search" name="q" value="<?=h($q)?>" placeholder="Search Member ID, Name or Mobile...">
        </div>
        <button type="submit" class="ml-btn-search">Search</button>
        <a class="ml-btn-export" href="?route=member-balances">Reset</a>
      </form>

      <div class="ml-stats mb-stats">
        <div class="ml-stat blue"><div class="ml-stat-icon">₹</div><div><span>Paid Contribution</span><b><?=money($totDeposits)?></b></div></div>
        <div class="ml-stat green"><div class="ml-stat-icon">📈</div><div><span>Interest Earned</span><b><?=money($totInterest)?></b></div></div>
        <div class="ml-stat orange"><div class="ml-stat-icon">↩</div><div><span>Approved Refund</span><b><?=money($totRefunds)?></b></div></div>
        <div class="ml-stat purple"><div class="ml-stat-icon">🏦</div><div><span>Loan Outstanding</span><b><?=money($totOutstanding)?></b></div></div>
        <div class="ml-stat blue mb-stat-wide"><div class="ml-stat-icon">✓</div><div><span>Available Balance Total</span><b><?=money($totAvailable)?></b></div></div>
      </div>

      <div class="ml-table-card">
        <div class="table-wrap">
          <table class="ml-table mb-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Member</th>
                <th>Staff</th>
                <th>Contribution</th>
                <th>Interest</th>
                <th>Refund</th>
                <th>Available</th>
                <th>Loan Out.</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <?php if(!$data): ?>
                <tr><td colspan="10" class="ml-empty">कोई Member नहीं मिला।</td></tr>
              <?php else: $i=1; foreach($data as $r):
                $st=trim((string)($r['status']??'Active'));
              ?>
              <tr>
                <td><?=$i++?></td>
                <td>
                  <b><?=h($r['name'])?></b>
                  <div class="mb-sub"><span class="ml-code"><?=h($r['code'])?></span> · <?=h($r['mobile'])?></div>
                </td>
                <td><?=h($r['staff_names']?:'Not assigned')?></td>
                <td><?=money((float)$r['deposits'])?></td>
                <td><?=money((float)$r['interest'])?></td>
                <td><?=money((float)$r['refunds'])?></td>
                <td><b class="mb-available"><?=money((float)$r['available'])?></b></td>
                <td><?=money((float)$r['loan_outstanding'])?></td>
                <td>
                  <?php if($st==='Active'): ?><span class="ml-status active">✓ Active</span>
                  <?php elseif($st==='Closed'): ?><span class="ml-status closed">Closed</span>
                  <?php else: ?><span class="ml-status inactive"><?=h($st)?></span><?php endif; ?>
                </td>
                <td class="ml-actions">
                  <a class="ml-act view" href="?route=member-view&id=<?=(int)$r['id']?>">👁 View</a>
                </td>
              </tr>
              <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
        <div class="ml-footer">
          <span>Showing <?=number_format($rowCount)?> members</span>
          <small class="muted">Closed member available = ₹0 · Loan outstanding अलग दिखता है</small>
        </div>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Member Available Balance',$c); exit;
}

if($route==='staff-member-users'){
    requireRole(['admin']);
    $msg=''; $msgType='success';
    $staffCapLabels=['dashboard'=>'Dashboard','members'=>'Members / Member Directory','contributions'=>'Contributions','loans'=>'Loans & EMI','payments'=>'Payment Verification','reports'=>'Reports','reminders'=>'Contribution & EMI Reminders','notifications'=>'Notifications'];
    $staffCapKeys=array_keys($staffCapLabels);
    $saveStaffCaps=function(int $userId,array $caps) use ($db): void { $db->exec('DELETE FROM admin_permissions WHERE user_id='.(int)$userId); foreach($caps as $cap){$st=$db->prepare('INSERT OR IGNORE INTO admin_permissions(user_id,capability) VALUES(?,?)');$st->bindValue(1,$userId,SQLITE3_INTEGER);$st->bindValue(2,$cap,SQLITE3_TEXT);$st->execute();} };
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $action=$_POST['action']??'';
        try {
            if($action==='save'){
                $id=(int)($_POST['id']??0);
                $role=$_POST['role']??'';
                if(!in_array($role,['staff','member'],true)) throw new RuntimeException('Invalid account role.');
                $username=trim($_POST['username']??'');
                $display=trim($_POST['display_name']??'');
                $memberName=trim($_POST['member_name']??'');
                $password=(string)($_POST['password']??'');
                $caps=array_values(array_unique(array_filter((array)($_POST['caps']??[]),fn($x)=>in_array($x,$staffCapKeys,true))));
                if($username==='') throw new RuntimeException('Login ID is required.');
                if(!preg_match('/^[A-Za-z0-9._@-]{3,60}$/',$username)) throw new RuntimeException('Login ID can contain letters, numbers, dot, underscore, @ and hyphen only.');
                $dup=$db->prepare("SELECT id FROM users WHERE username=? AND id<>?"); $dup->bindValue(1,$username,SQLITE3_TEXT); $dup->bindValue(2,$id,SQLITE3_INTEGER);
                if($dup->execute()->fetchArray(SQLITE3_ASSOC)) throw new RuntimeException('This Login ID is already in use.');
                if($password!=='' && strlen($password)<6) throw new RuntimeException('Password must be at least 6 characters.');
                if($id>0){
                    $old=$db->prepare("SELECT * FROM users WHERE id=? AND role=?"); $old->bindValue(1,$id,SQLITE3_INTEGER); $old->bindValue(2,$role,SQLITE3_TEXT); $row=$old->execute()->fetchArray(SQLITE3_ASSOC);
                    if(!$row) throw new RuntimeException('Account not found or role mismatch.');
                    if($password!==''){
                        $st=$db->prepare("UPDATE users SET username=?,display_name=?,password_hash=? WHERE id=? AND role=?");
                        $st->bindValue(3,password_hash($password,PASSWORD_DEFAULT),SQLITE3_TEXT); $st->bindValue(4,$id,SQLITE3_INTEGER); $st->bindValue(5,$role,SQLITE3_TEXT);
                    } else {
                        $st=$db->prepare("UPDATE users SET username=?,display_name=? WHERE id=? AND role=?");
                        $st->bindValue(3,$id,SQLITE3_INTEGER); $st->bindValue(4,$role,SQLITE3_TEXT);
                    }
                    $st->bindValue(1,$username,SQLITE3_TEXT); $st->bindValue(2,$display,SQLITE3_TEXT); $st->execute();
                    if($role==='member' && !empty($row['member_id']) && $memberName!==''){
                        $st=$db->prepare("UPDATE members SET name=? WHERE id=?"); $st->bindValue(1,$memberName,SQLITE3_TEXT); $st->bindValue(2,(int)$row['member_id'],SQLITE3_INTEGER); $st->execute();
                    }
                    if($role==='staff') $saveStaffCaps($id,$caps);
                    $msg=ucfirst($role).' account updated successfully.';
                } else {
                    if(strlen($password)<6) throw new RuntimeException('Password must be at least 6 characters.');
                    if($role==='staff'){
                        $st=$db->prepare("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)");
                        $st->bindValue(1,$username,SQLITE3_TEXT); $st->bindValue(2,password_hash($password,PASSWORD_DEFAULT),SQLITE3_TEXT); $st->bindValue(3,'staff',SQLITE3_TEXT); $st->bindValue(4,$display ?: $username,SQLITE3_TEXT); $st->execute();
                        $saveStaffCaps((int)$db->lastInsertRowID(),$caps);
                    } else {
                        $mid=(int)($_POST['member_id']??0);
                        if($mid<=0) throw new RuntimeException('Select a Member for the Member login.');
                        $existing=$db->prepare("SELECT id FROM users WHERE role='member' AND member_id=?"); $existing->bindValue(1,$mid,SQLITE3_INTEGER);
                        if($existing->execute()->fetchArray(SQLITE3_ASSOC)) throw new RuntimeException('This Member already has a login account.');
                        $mem=$db->prepare("SELECT name FROM members WHERE id=?"); $mem->bindValue(1,$mid,SQLITE3_INTEGER); $mr=$mem->execute()->fetchArray(SQLITE3_ASSOC); if(!$mr) throw new RuntimeException('Member not found.');
                        $st=$db->prepare("INSERT INTO users(username,password_hash,role,member_id,display_name) VALUES(?,?,?,?,?)");
                        $st->bindValue(1,$username,SQLITE3_TEXT); $st->bindValue(2,password_hash($password,PASSWORD_DEFAULT),SQLITE3_TEXT); $st->bindValue(3,'member',SQLITE3_TEXT); $st->bindValue(4,$mid,SQLITE3_INTEGER); $st->bindValue(5,$display ?: $mr['name'],SQLITE3_TEXT); $st->execute();
                    }
                    $msg='New '.ucfirst($role).' account created successfully.';
                }
            } elseif($action==='delete'){
                $id=(int)($_POST['id']??0); $role=$_POST['role']??'';
                if(!in_array($role,['staff','member'],true)) throw new RuntimeException('Invalid account role.');
                if($id===(int)user()['id']) throw new RuntimeException('You cannot delete the currently logged-in account.');
                $st=$db->prepare("DELETE FROM users WHERE id=? AND role=?"); $st->bindValue(1,$id,SQLITE3_INTEGER); $st->bindValue(2,$role,SQLITE3_TEXT); $st->execute();
                $msg=ucfirst($role).' account deleted.';
            }
        } catch(Throwable $e){ $msg=$e->getMessage(); $msgType='danger'; }
    }
    $editId=(int)($_GET['edit']??0); $edit=null; $editMember=null; $editCaps=$staffCapKeys;
    if($editId){ $st=$db->prepare("SELECT id,username,display_name,role,member_id,created_at FROM users WHERE id=? AND role IN ('staff','member')"); $st->bindValue(1,$editId,SQLITE3_INTEGER); $edit=$st->execute()->fetchArray(SQLITE3_ASSOC) ?: null; if($edit && $edit['member_id']){$ms=$db->prepare("SELECT id,name,code FROM members WHERE id=?");$ms->bindValue(1,(int)$edit['member_id'],SQLITE3_INTEGER);$editMember=$ms->execute()->fetchArray(SQLITE3_ASSOC) ?: null;} if($edit && $edit['role']==='staff'){ $editCaps=[]; $pr=$db->prepare('SELECT capability FROM admin_permissions WHERE user_id=?');$pr->bindValue(1,$editId,SQLITE3_INTEGER);$rr=$pr->execute();while($pp=$rr->fetchArray(SQLITE3_ASSOC))$editCaps[]=$pp['capability']; if(!$editCaps)$editCaps=$staffCapKeys; }}
    $staff=$db->query("SELECT id,username,display_name,created_at FROM users WHERE role='staff' ORDER BY id ASC");
    $members=$db->query("SELECT u.id,u.username,u.display_name,u.created_at,m.id member_id,m.name,m.code FROM users u LEFT JOIN members m ON m.id=u.member_id WHERE u.role='member' ORDER BY u.id ASC");
    $allMembers=$db->query("SELECT m.id,m.name,m.code,m.mobile,m.status,u.id AS user_id,u.username FROM members m LEFT JOIN users u ON u.member_id=m.id AND u.role='member' ORDER BY m.name COLLATE NOCASE");
    $prefillMemberId=(int)($_GET['member_id']??0);
    $availableMembers=$db->query("SELECT m.id,m.name,m.code FROM members m LEFT JOIN users u ON u.member_id=m.id AND u.role='member' WHERE u.id IS NULL ORDER BY m.name ASC");
    ob_start(); ?>
    <div class="page-title"><div><div class="eyebrow">ACCOUNT CONTROL</div><h1>Staff & Member IDs</h1><p>Admin can create, edit and manage Staff/Member login IDs, names and passwords. <span class="hi-sub">स्टाफ और सदस्य की लॉगिन आईडी, नाम और पासवर्ड यहाँ बदलें।</span></p></div></div>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2><?= $edit ? 'Edit '.ucfirst($edit['role']).' Account' : 'Create Account' ?></h2><span class="badge success">Admin Only</span></div>
        <?php if($msg): ?><div class="alert <?=h($msgType)?> account-update-message" role="status"><?=h($msg)?></div><?php endif; ?>
        <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="action" value="save"><input type="hidden" name="id" value="<?=h((string)($edit['id']??0))?>">
          <?php if(!$edit): ?><div><label>Account Type</label><select name="role" id="account-role" onchange="var isMember=this.value==='member';document.getElementById('member-pick').style.display=isMember?'block':'none';document.getElementById('staff-permissions').style.display=isMember?'none':'block'"><option value="staff" <?=$prefillMemberId>0?'':'selected'?>>Staff</option><option value="member" <?=$prefillMemberId>0?'selected':''?>>Member</option></select></div><?php else: ?><input type="hidden" name="role" value="<?=h($edit['role'])?>"><div><label>Account Type</label><input value="<?=h(ucfirst($edit['role']))?>" disabled></div><?php endif; ?>
          <div><label>Login ID / Username</label><input name="username" value="<?=h($edit['username']??'')?>" required></div>
          <div><label>Display Name</label><input name="display_name" value="<?=h($edit['display_name']??($editMember['name']??''))?>" required></div>
          <div id="member-pick" style="<?=($edit && $edit['role']==='member')||$prefillMemberId>0?'':'display:none'?>"><label>Select Member</label><select name="member_id"><?php if($editMember): ?><option value="<?=$editMember['id']?>"><?=h($editMember['code'].' — '.$editMember['name'])?></option><?php endif; while($am=$availableMembers->fetchArray(SQLITE3_ASSOC)): ?><option value="<?=$am['id']?>" <?=$prefillMemberId===(int)$am['id']?'selected':''?>><?=h($am['code'].' — '.$am['name'])?></option><?php endwhile; ?></select></div>
          <?php if($edit && $edit['role']==='member'): ?><div><label>Member Name</label><input name="member_name" value="<?=h($editMember['name']??'')?>"></div><?php endif; ?>
          <div class="span2 account-password-field"><label>Password <?= $edit ? '(leave blank to keep current)' : '' ?></label><div class="password-field-wrap"><input name="password" type="password" minlength="6" autocomplete="new-password" <?= $edit ? '' : 'required' ?> placeholder="Enter minimum 6 characters" aria-label="Account password"><button type="button" class="btn small password-toggle" onclick="togglePasswordVisibility(this)" aria-label="Show or hide password">Show</button></div><small class="muted">Password securely hash होकर save होगा. Existing password बदलना न हो तो edit करते समय box खाली छोड़ें.</small></div>
          <div id="staff-permissions" class="span2 staff-permissions-box" style="<?=($edit && $edit['role']==='member')?'display:none':''?>"><div class="form-section-heading"><b>Permissions / अधिकार</b><small>Staff को केवल चुने हुए sections दिखाई देंगे और वही open कर पाएगा.</small></div><div class="staff-permission-grid"><?php foreach($staffCapLabels as $capKey=>$capLabel): ?><label class="permission-option"><input type="checkbox" name="caps[]" value="<?=h($capKey)?>" <?=in_array($capKey,$editCaps,true)?'checked':''?>> <span><?=h($capLabel)?></span></label><?php endforeach; ?></div></div>
          <div class="span2"><button class="btn primary"><?= $edit ? 'Update Account' : 'Create Account' ?></button><?php if($edit): ?> <a class="btn" href="?route=staff-member-users">Cancel</a><?php endif; ?></div>
        </form>
      </div>
      <div class="ml-table-card staff-accounts-card">
        <div class="ml-footer" style="border-bottom:1px solid #eef2f7;border-top:0"><span><b>Staff Accounts</b></span><span class="badge info">Staff</span></div>
        <div class="table-wrap">
          <table class="ml-table gs-data-table">
            <thead><tr><th>#</th><th>Name</th><th>Login ID</th><th>Created</th><th>Action</th></tr></thead>
            <tbody>
              <?php $si=1; $hasStaff=false; while($a=$staff->fetchArray(SQLITE3_ASSOC)): $hasStaff=true; ?>
              <tr>
                <td><?=$si++?></td>
                <td><b><?=h($a['display_name']?:$a['username'])?></b></td>
                <td><span class="ml-code"><?=h($a['username'])?></span></td>
                <td><?=h($a['created_at'])?></td>
                <td class="ml-actions">
                  <a class="ml-act edit" href="?route=staff-member-users&edit=<?=$a['id']?>">✎ Edit</a>
                  <form method="post" style="display:inline;margin:0" onsubmit="return confirm('Delete this Staff account?');">
                    <input type="hidden" name="csrf" value="<?=h(csrf())?>">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="<?=$a['id']?>">
                    <input type="hidden" name="role" value="staff">
                    <button class="ml-act delete" type="submit" style="border:0;cursor:pointer">🗑 Delete</button>
                  </form>
                </td>
              </tr>
              <?php endwhile; if(!$hasStaff): ?>
              <tr><td colspan="5" class="ml-empty">No staff accounts yet.</td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="ml-table-card all-members-account-panel" style="margin-top:16px">
      <div class="ml-footer" style="border-bottom:1px solid #eef2f7;border-top:0">
        <span><b>All Members / सभी सदस्य</b> · login status · edit account</span>
        <span class="badge info">Member Directory</span>
      </div>
      <div class="table-wrap">
        <table class="ml-table gs-data-table all-members-account-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Member ID</th>
              <th>Name</th>
              <th>Mobile</th>
              <th>Status</th>
              <th>Login</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <?php $hasAllMembers=false; $ai=1; while($a=$allMembers->fetchArray(SQLITE3_ASSOC)): $hasAllMembers=true;
              $st=trim((string)($a['status']??''));
            ?>
            <tr>
              <td><?=$ai++?></td>
              <td><span class="ml-code"><?=h($a['code'])?></span></td>
              <td><b><?=h($a['name'])?></b></td>
              <td><?=h($a['mobile']?:'—')?></td>
              <td>
                <?php if($st==='Active'): ?><span class="ml-status active">✓ Active</span>
                <?php elseif($st==='Closed'): ?><span class="ml-status closed">Closed</span>
                <?php else: ?><span class="ml-status inactive"><?=h($st?:'Not set')?></span><?php endif; ?>
              </td>
              <td><?=!empty($a['user_id'])?'<span class="ml-status active">Created</span>':'<span class="ml-status inactive">Not created</span>'?></td>
              <td class="ml-actions">
                <?php if(!empty($a['user_id'])): ?>
                  <a class="ml-act edit" href="?route=staff-member-users&amp;edit=<?=$a['user_id']?>">✎ Edit Login</a>
                <?php else: ?>
                  <a class="ml-act view" href="?route=staff-member-users&amp;member_id=<?=$a['id']?>">+ Create Login</a>
                <?php endif; ?>
              </td>
            </tr>
            <?php endwhile; if(!$hasAllMembers): ?>
            <tr><td colspan="7" class="ml-empty">No members found.</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php $c=ob_get_clean(); layout('Staff & Member IDs',$c); exit;
}

if($route==='whatsapp-media'){
    requireRole(['admin','staff']);
    $id=(int)($_GET['id']??0); if($id<1){http_response_code(404);exit;}
    $st=$db->prepare("SELECT media_file,media_mime,media_name FROM whatsapp_messages WHERE id=? AND media_file<>''"); $st->bindValue(1,$id,SQLITE3_INTEGER); $row=$st->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$row || !is_file(__DIR__.'/'.$row['media_file'])){http_response_code(404);exit;}
    header('Content-Type: '.($row['media_mime']?:'application/octet-stream')); header('Content-Disposition: inline; filename="'.str_replace('"','',($row['media_name']?:basename($row['media_file']))).'"'); header('X-Content-Type-Options: nosniff'); readfile(__DIR__.'/'.$row['media_file']); exit;
}

if($route==='whatsapp-call-webhook'){
    // Public Meta webhook endpoint. No login required.
    $verify=trim((string)getSetting('whatsapp_webhook_verify_token',''));
    if($_SERVER['REQUEST_METHOD']==='GET'){
        $mode=(string)($_GET['hub_mode']??$_GET['hub.mode']??'');
        $token=(string)($_GET['hub_verify_token']??$_GET['hub.verify_token']??'');
        $challenge=(string)($_GET['hub_challenge']??$_GET['hub.challenge']??'');
        if($mode==='subscribe' && $verify!=='' && hash_equals($verify,$token)){ header('Content-Type:text/plain'); echo $challenge; exit; }
        http_response_code(403); echo 'Webhook verification failed'; exit;
    }
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $raw=file_get_contents('php://input');
        $payload=json_decode((string)$raw,true);
        if(is_array($payload)){
            foreach(($payload['entry']??[]) as $entry){
                foreach(($entry['changes']??[]) as $change){
                    $value=$change['value']??[];
                    foreach(($value['messages']??[]) as $wm){
                        $from=(string)($wm['from']??''); $type=(string)($wm['type']??'text'); $body=(string)($wm['text']['body']??($wm['button']['text']??$wm['interactive']['button_reply']['title']??''));
                        $mediaId=''; $mediaMime=''; $mediaFile=''; $mediaName='';
                        if(in_array($type,['image','video','audio','document'],true)){
                            $media=$wm[$type]??[]; $mediaId=(string)($media['id']??''); $mediaMime=(string)($media['mime_type']??''); $mediaName=(string)($media['filename']??($type.'.file'));
                            $body=$type==='image'?'📷 Image':($type==='video'?'🎥 Video':($type==='audio'?'🎵 Audio':'📄 Document'));
                            [$saved,$mediaFile,$savedMime]=whatsappDownloadMedia($mediaId,$mediaMime,$mediaName); if($saved)$mediaMime=$savedMime;
                            if(isset($media['caption'])) $body=trim($body.' '.(string)$media['caption']);
                        }
                        $contactName=(string)($value['contacts'][0]['profile']['name']??'');
                        $memberId=null; $q=$db->prepare("SELECT id FROM members WHERE REPLACE(REPLACE(REPLACE(REPLACE(mobile,'+',''),' ',''),'-',''),'(', '') LIKE ? LIMIT 1"); $q->bindValue(1,'%'.preg_replace('/\D+/','',$from).'%'); $mr=$q->execute()->fetchArray(SQLITE3_ASSOC); if($mr)$memberId=(int)$mr['id'];
                        whatsappLogMessage($from,$contactName,'inbound',$type,$body,'received',(string)($wm['id']??''),$memberId,(string)$raw,$mediaId,$mediaMime,$mediaFile,$mediaName);
                    }
                    foreach(($value['statuses']??[]) as $ws){
                        $mid=(string)($ws['id']??''); $status=(string)($ws['status']??''); if($mid!==''){ $st=$db->prepare("UPDATE whatsapp_messages SET status=? WHERE meta_message_id=?");$st->bindValue(1,$status);$st->bindValue(2,$mid);$st->execute(); }
                    }
                    $changeJson=json_encode($change,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
                    if(stripos((string)$changeJson,'call')!==false){
                        $mobile=(string)($value['contacts'][0]['wa_id']??''); $st=$db->prepare("INSERT INTO whatsapp_call_logs(mobile,call_type,call_status,meta_call_id,raw_payload) VALUES(?,?,?,?,?)"); $st->bindValue(1,$mobile,SQLITE3_TEXT); $st->bindValue(2,'WhatsApp Call',SQLITE3_TEXT); $st->bindValue(3,'event',SQLITE3_TEXT); $st->bindValue(4,'',SQLITE3_TEXT); $st->bindValue(5,$changeJson,SQLITE3_TEXT); $st->execute();
                    }
                }
            }
        }
        $dir=__DIR__.'/data'; if(!is_dir($dir)) @mkdir($dir,0775,true);
        $line=date('c').' '.hash('sha256',(string)($_SERVER['REMOTE_ADDR']??'')).' '.substr((string)$raw,0,12000).PHP_EOL;
        @file_put_contents($dir.'/whatsapp_call_webhook.log',$line,FILE_APPEND|LOCK_EX);
        header('Content-Type: application/json'); echo json_encode(['ok'=>true]); exit;
    }
    http_response_code(405); exit;
}

if($route==='whatsapp-embedded-callback'){
    requireRole(['admin']);
    if($_SERVER['REQUEST_METHOD']!=='POST'){ http_response_code(405); echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    checkCsrf(); header('Content-Type: application/json; charset=utf-8');
    $code=trim((string)($_POST['code']??'')); $waba=trim((string)($_POST['waba_id']??'')); $phone=trim((string)($_POST['phone_number_id']??'')); $business=trim((string)($_POST['business_id']??'')); $eventRaw=(string)($_POST['session_event']??'');
    if($waba!=='') setSetting('whatsapp_waba_id',$waba); if($phone!=='') setSetting('whatsapp_phone_number_id',preg_replace('/\D+/','',$phone)); if($business!=='') setSetting('whatsapp_business_id',$business); if($eventRaw!=='') setSetting('whatsapp_embedded_last_status',substr($eventRaw,0,4000));
    if($code===''){ setSetting('whatsapp_embedded_last_status','Signup session event received; waiting for Meta response code.'); echo json_encode(['ok'=>true,'message'=>'Signup session event received.']); exit; }
    $appId=trim((string)getSetting('whatsapp_app_id','')); if($appId==='') $appId='2161510128110351'; $secret=trim((string)getSetting('whatsapp_app_secret','')); $gv=trim((string)getSetting('whatsapp_graph_version','v25.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
    if($appId==='' || $secret===''){ setSetting('whatsapp_embedded_last_status','Signup completed, but App Secret is missing; exchangeable code received.'); echo json_encode(['ok'=>true,'message'=>'Signup complete. App Secret add karke token exchange complete karein.','code_received'=>true]); exit; }
    if(!function_exists('curl_init')){ echo json_encode(['ok'=>false,'error'=>'PHP cURL extension is required for Embedded Signup token exchange.']); exit; }
    $url='https://graph.facebook.com/'.rawurlencode($gv).'/oauth/access_token?client_id='.rawurlencode($appId).'&client_secret='.rawurlencode($secret).'&code='.rawurlencode($code);
    $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>25,CURLOPT_HTTPGET=>true]); $resp=curl_exec($ch); $ce=curl_error($ch); $status=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch); $json=json_decode((string)$resp,true);
    if($ce || $status<200 || $status>=300 || !is_array($json) || empty($json['access_token'])){ setSetting('whatsapp_embedded_last_status','Token exchange failed: '.substr((string)$resp,0,1500)); echo json_encode(['ok'=>false,'error'=>'Meta token exchange failed'.($status?' (HTTP '.$status.')':'').($ce?': '.$ce:'').(isset($json['error']['message'])?' — '.$json['error']['message']:'')]); exit; }
    setSetting('whatsapp_api_key',(string)$json['access_token']); setSetting('whatsapp_embedded_last_status','Embedded Signup v4 connected successfully on '.date('c')); audit('whatsapp_embedded_signup','Embedded Signup v4 / Coexistence connection completed'.($waba?' WABA='.$waba:'').($phone?' PhoneID='.$phone:''));
    echo json_encode(['ok'=>true,'connected'=>true,'message'=>'WhatsApp Business App + Cloud API connection completed.','waba_id'=>getSetting('whatsapp_waba_id',''),'phone_number_id'=>getSetting('whatsapp_phone_number_id','')]); exit;
}

if($route==='whatsapp-center'){
    $requestedWaTab=(string)($_GET['tab']??'home');
    $tab=in_array($requestedWaTab,['home','bulk','payment','logs'],true)?$requestedWaTab:'home';
    $chatOnly=$tab==='home' && (string)($_GET['chat_only']??'')==='1';
    requireRole(['admin']);
    $msg=''; $err='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=(string)($_POST['wa_action']??'');
        if($action==='delete_chat'){
            $mobile=preg_replace('/[^0-9+]/','',(string)($_POST['chat_mobile']??''));
            if($mobile==='') $err='Chat not found.';
            else {
                $st=$db->prepare("SELECT id,media_file FROM whatsapp_messages WHERE mobile=?"); $st->bindValue(1,$mobile,SQLITE3_TEXT); $rr=$st->execute();
                while($mr=$rr->fetchArray(SQLITE3_ASSOC)){ $mf=(string)($mr['media_file']??''); if($mf!=='' && str_starts_with($mf,'uploads/whatsapp_media/')) { $fp=__DIR__.'/'.$mf; if(is_file($fp)) @unlink($fp); } }
                $st=$db->prepare("DELETE FROM whatsapp_messages WHERE mobile=?"); $st->bindValue(1,$mobile,SQLITE3_TEXT); $st->execute();
                audit('whatsapp_chat_deleted','Chat deleted for '.$mobile); $msg='Chat conversation deleted.'; 
            }
        } elseif($action==='send_message'){
            $mid=(int)($_POST['member_id']??0); $text=trim((string)($_POST['message']??''));
            $expectedMobile=preg_replace('/\D+/','',(string)($_POST['chat_mobile']??''));
            $m=null; if($mid){ $st=$db->prepare("SELECT id,name,code,mobile FROM members WHERE id=?"); $st->bindValue(1,$mid,SQLITE3_INTEGER); $m=$st->execute()->fetchArray(SQLITE3_ASSOC); }
            $actualMobile=$m?preg_replace('/\D+/','',(string)($m['mobile']??'')):'';
            // Conversation mobile can include country code while member record stores a local Indian 10-digit number.
            $expectedComparable=strlen($expectedMobile)>=10?substr($expectedMobile,-10):$expectedMobile;
            $actualComparable=strlen($actualMobile)>=10?substr($actualMobile,-10):$actualMobile;
            $hasFile=isset($_FILES['chat_image']) && (($_FILES['chat_image']['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_NO_FILE);
            if(!$m || $expectedMobile==='' || $actualMobile==='' || strlen($expectedComparable)!==10 || $expectedComparable!==$actualComparable) $err='सुरक्षा के लिए मैसेज नहीं भेजा गया: चुनी हुई चैट और सदस्य का मोबाइल नंबर मेल नहीं खाता। Chat को refresh करके सही ग्राहक चुनें।';
            elseif($text==='' && !$hasFile) $err='Message या image चुनें।';
            elseif($hasFile && (($_FILES['chat_image']['error']??UPLOAD_ERR_OK)!==UPLOAD_ERR_OK)) $err='Image upload failed.';
            else {
                // Send to the exact WhatsApp conversation number selected by the operator, after the member-number match passes.
                $m['mobile']=$expectedMobile;
                if($hasFile) [$ok,$info]=whatsappSendImageToMember($m,$_FILES['chat_image'],$text);
                else [$ok,$info]=whatsappSendTextToMember($m,$text);
                if($ok){$msg=$hasFile?'WhatsApp image/message sent successfully.':'WhatsApp message sent successfully.';audit('whatsapp_message_sent',($hasFile?'Image/message':'Message').' sent to '.$m['name'].' ('.$m['code'].')');}
                else $err=$info;
            }
        } elseif($action==='bulk_message'){
            if(getSetting('whatsapp_bulk_enabled','0')!=='1' && !isSuperAdmin()) $err='Bulk messaging अभी disabled है। पहले WhatsApp Center settings में ON करें।';
            else { $text=trim((string)($_POST['bulk_message']??'')); $limit=max(1,min(100,(int)($_POST['bulk_limit']??50))); $sent=0;$failed=0; if($text==='')$err='Bulk message खाली है.'; else { $r=$db->query("SELECT id,name,code,mobile FROM members WHERE status='Active' AND TRIM(COALESCE(mobile,''))<>'' ORDER BY id DESC LIMIT ".$limit); while($m=$r->fetchArray(SQLITE3_ASSOC)){ [$ok,$info]=whatsappSendTextToMember($m,$text); $ok?$sent++:$failed++; } $msg="Bulk send complete: {$sent} sent, {$failed} failed."; audit('whatsapp_bulk_sent',"Sent={$sent}, Failed={$failed}"); } }
        } elseif($action==='save_center'){
            $keys=['whatsapp_app_id','whatsapp_app_secret','whatsapp_config_id','whatsapp_graph_version','whatsapp_webhook_verify_token','whatsapp_embedded_signup_enabled','whatsapp_embedded_signup_version','whatsapp_coexistence_enabled','whatsapp_session_logging_enabled','whatsapp_template_name','whatsapp_template_language','whatsapp_welcome_template_name','whatsapp_welcome_template_language','whatsapp_closure_template_name','whatsapp_closure_template_language','whatsapp_auto_emi_enabled','whatsapp_auto_contribution_enabled','whatsapp_auto_payment_enabled','whatsapp_auto_welcome_enabled','whatsapp_auto_loan_application_enabled','whatsapp_auto_loan_approved_enabled','whatsapp_auto_loan_rejected_enabled','whatsapp_auto_loan_disbursed_enabled','whatsapp_auto_emi_paid_enabled','whatsapp_auto_refund_enabled','whatsapp_template_contribution_name','whatsapp_template_contribution_language','whatsapp_template_loan_application_name','whatsapp_template_loan_application_language','whatsapp_template_loan_approved_name','whatsapp_template_loan_approved_language','whatsapp_template_loan_rejected_name','whatsapp_template_loan_rejected_language','whatsapp_template_loan_disbursed_name','whatsapp_template_loan_disbursed_language','whatsapp_template_emi_paid_name','whatsapp_template_emi_paid_language','whatsapp_bulk_enabled','whatsapp_staff_send_enabled'];
            foreach($keys as $k){ if(!array_key_exists($k,$_POST)) continue; $v=trim((string)$_POST[$k]); if(str_ends_with($k,'_enabled'))$v=$v==='1'?'1':'0'; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");$st->bindValue(1,$k,SQLITE3_TEXT);$st->bindValue(2,$v,SQLITE3_TEXT);$st->execute();}
            audit('whatsapp_center_settings_updated','WhatsApp Center settings updated');$msg='WhatsApp Center settings saved.';
        }
    }
    $memberRows=$db->query("SELECT id,name,code,mobile FROM members WHERE status='Active' ORDER BY name COLLATE NOCASE LIMIT 500");
    $chatMemberRows=[]; $chatMemberResult=$db->query("SELECT id,name,code,mobile,photo FROM members WHERE status='Active' AND TRIM(COALESCE(mobile,''))<>'' ORDER BY name COLLATE NOCASE LIMIT 1000"); while($chatMemberResult && ($chatMemberRow=$chatMemberResult->fetchArray(SQLITE3_ASSOC))) $chatMemberRows[]=$chatMemberRow;
    $logs=$db->query("SELECT w.*,m.code FROM whatsapp_messages w LEFT JOIN members m ON m.id=w.member_id ORDER BY w.id DESC");
    $paidEmi=$db->query("SELECT p.id,p.created_at,p.amount,m.name,m.code,e.installment_no FROM payments p LEFT JOIN emi_schedule e ON e.id=p.emi_id JOIN members m ON m.id=p.member_id WHERE p.status='Paid' ORDER BY p.id DESC LIMIT 30");
    $paidContrib=$db->query("SELECT c.id,c.created_at,c.amount,c.month,m.name,m.code FROM contributions c JOIN members m ON m.id=c.member_id WHERE c.status='Paid' ORDER BY c.id DESC LIMIT 30");
    $totalMessages=(int)$db->querySingle("SELECT COUNT(*) FROM whatsapp_messages"); $incomingMessages=(int)$db->querySingle("SELECT COUNT(*) FROM whatsapp_messages WHERE direction='inbound'"); $sentMessages=(int)$db->querySingle("SELECT COUNT(*) FROM whatsapp_messages WHERE direction='outbound' AND status='sent'"); $callCount=(int)$db->querySingle("SELECT COUNT(*) FROM whatsapp_call_logs");
    $webhookUrl=siteBaseUrl().'?route=whatsapp-call-webhook';
    $embedReady=(getSetting('whatsapp_app_id','')!=='' && getSetting('whatsapp_config_id','')!=='');
    ob_start(); ?>
    <style>
    .wa-center-page{font-family:Inter,Segoe UI,Arial,sans-serif;color:#17304f}
    .wa-center-page .wa-hero{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:18px;padding:22px 24px;border:1px solid #dfe7f1;border-radius:18px;background:linear-gradient(135deg,#ffffff,#f6faff);box-shadow:0 10px 28px rgba(20,40,70,.07)}
    .wa-center-page .wa-hero h1{margin:4px 0 7px;font-size:28px;line-height:1.15}.wa-center-page .wa-hero p{margin:0;color:#65758b;line-height:1.5}.wa-center-page .wa-hero-icon{width:58px;height:58px;border-radius:16px;display:flex;align-items:center;justify-content:center;background:#eaf3ff;font-size:30px;flex:0 0 58px}
    .wa-center-page .wa-compose{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.wa-center-page .wa-attach-btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid #d7e0eb;background:#fff;border-radius:10px;padding:10px 12px;cursor:pointer;font-weight:700;white-space:nowrap}.wa-center-page .wa-image-preview{font-size:12px;color:#176b43;max-width:100%;overflow-wrap:anywhere}.wa-center-page .wa-compose textarea{flex:1;min-width:100px}.wa-center-page .wa-chat-header form{display:inline-flex}@media(max-width:560px){.wa-center-page .wa-compose{gap:6px}.wa-center-page .wa-attach-btn{padding:9px 10px}.wa-center-page .wa-compose button{padding:10px 12px}}.wa-center-page .wa-tabs{display:flex;gap:9px;flex-wrap:wrap;margin:0 0 18px}.wa-center-page .wa-tabs a{display:inline-flex!important;align-items:center;justify-content:center;padding:11px 15px;border:1px solid #d7e0eb;border-radius:11px;background:#fff;color:#17304f;text-decoration:none;font-weight:800;box-shadow:0 3px 10px rgba(20,40,70,.04)}.wa-center-page .wa-tabs a.active,.wa-center-page .wa-tabs a:hover{background:#1468d4;color:#fff;border-color:#1468d4}
    .wa-center-page .wa-stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 18px}.wa-center-page .wa-stat{background:#fff;border:1px solid #e3e8f0;border-radius:15px;padding:15px 16px;box-shadow:0 7px 20px rgba(20,40,70,.06)}.wa-center-page .wa-stat span{display:block;color:#718097;font-size:12px;font-weight:700}.wa-center-page .wa-stat b{display:block;font-size:25px;margin-top:6px;color:#172b46}.wa-center-page .wa-stat small{display:block;margin-top:4px;color:#8a97a8}
    .wa-center-page .wa-content{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.wa-center-page .panel{background:#fff;border:1px solid #e1e7ef;border-radius:17px;padding:18px;box-shadow:0 9px 25px rgba(20,40,70,.065)}.wa-center-page .panel h2,.wa-center-page .panel h3{margin-top:0}.wa-center-page .wa-wide{grid-column:1/-1}.wa-center-page .wa-empty{padding:26px;text-align:center;color:#718097;border:1px dashed #d5deea;border-radius:13px;background:#fbfdff}.wa-center-page .wa-quick{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.wa-center-page .wa-quick a{display:block;padding:13px;border:1px solid #e0e7f0;border-radius:12px;background:#fbfdff;text-decoration:none;color:#17304f;font-weight:800}.wa-center-page .wa-quick a:hover{border-color:#1468d4;background:#f3f8ff}
    @media(max-width:850px){.wa-center-page .wa-stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.wa-center-page .wa-content{grid-template-columns:1fr}.wa-center-page .wa-wide{grid-column:auto}}
    @media(max-width:700px){
      .wa-center-page .wa-hero{padding:16px;flex-direction:column;align-items:flex-start;background:linear-gradient(135deg,#0b5ed7 0%,#084298 55%,#052c65 100%);color:#fff;border:0}
      .wa-center-page .wa-hero h1{font-size:22px;color:#fff}.wa-center-page .wa-hero p{color:rgba(255,255,255,.88)}
      .wa-center-page .wa-hero-icon{background:rgba(255,255,255,.18);color:#fff}
      .wa-center-page .wa-stat-grid{grid-template-columns:1fr 1fr;gap:10px}
      .wa-center-page .wa-stat{border-radius:14px;padding:12px 14px}
      .wa-center-page .wa-stat b{font-size:20px}
      .wa-center-page .wa-tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px}
      .wa-center-page .wa-tabs a{min-width:0;padding:10px 8px;font-size:12px;text-align:center}
      .wa-center-page .wa-quick{grid-template-columns:1fr}
      .wa-center-page .wa-compose{flex-direction:column;align-items:stretch}
      .wa-center-page .wa-compose textarea{width:100%;min-height:70px}
      .wa-center-page .wa-compose button,.wa-center-page .wa-attach-btn{width:100%}
    }
    /* Mobile inbox: list first; open chat on tap */
    @media(max-width:850px){
      .wa-center-page .wa-live-inbox{display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:0!important;min-height:72vh}
      .wa-center-page .wa-live-inbox[data-has-explicit-chat="0"] .wa-inbox-sidebar{display:flex!important;visibility:visible!important;width:100%!important;max-width:100%!important}
      .wa-center-page .wa-live-inbox[data-has-explicit-chat="0"] .wa-inbox-chat{display:none!important}
      .wa-center-page .wa-live-inbox[data-has-explicit-chat="1"] .wa-inbox-sidebar{display:none!important}
      .wa-center-page .wa-live-inbox[data-has-explicit-chat="1"] .wa-inbox-chat{display:flex!important;visibility:visible!important;width:100%!important;min-height:70vh}
      .wa-center-page .wa-conversation{padding:12px 14px}
      .wa-center-page .wa-message-scroll{max-height:48vh}
    }
    @media(max-width:850px){.wa-center-page.wa-chat-only .wa-live-inbox{position:relative!important;display:flex!important;flex-direction:column!important;height:calc(100dvh - 74px)!important;min-height:480px!important;max-height:none!important}.wa-center-page.wa-chat-only .wa-live-inbox[data-has-explicit-chat="0"] .wa-inbox-sidebar,.wa-center-page.wa-chat-only .wa-live-inbox[data-has-explicit-chat="1"] .wa-inbox-sidebar,.wa-center-page.wa-chat-only .wa-live-inbox .wa-inbox-sidebar{display:none!important;visibility:hidden!important;position:absolute!important;z-index:8!important;inset:0 auto 0 0!important;width:min(88%,360px)!important;height:100%!important;max-height:none!important}.wa-center-page.wa-chat-only .wa-live-inbox.show-member-list[data-has-explicit-chat="0"] .wa-inbox-sidebar,.wa-center-page.wa-chat-only .wa-live-inbox.show-member-list[data-has-explicit-chat="1"] .wa-inbox-sidebar,.wa-center-page.wa-chat-only .wa-live-inbox.show-member-list .wa-inbox-sidebar{display:flex!important;visibility:visible!important}.wa-center-page.wa-chat-only .wa-live-inbox .wa-inbox-chat{display:flex!important;visibility:visible!important;flex:1 1 auto!important;width:100%!important;height:100%!important;min-height:0!important;max-height:none!important}}
    </style><div class="wa-center-page <?= $chatOnly?'wa-chat-only':'' ?>"><div class="wa-hero"><div><div class="eyebrow">META BUSINESS MESSAGING</div><h1>💬 WhatsApp Center</h1><p>WhatsApp chat, bulk messaging, payment slips और chat logs को एक ही clean center से manage करें।</p></div><div class="wa-hero-icon">💬</div></div>
    <?php if($msg): ?><div class="alert success"><?=h($msg)?></div><?php endif; ?><?php if($err): ?><div class="alert danger"><?=h($err)?></div><?php endif; ?>
    <div class="wa-stat-grid"><div class="wa-stat"><span>Total Messages</span><b><?=number_format($totalMessages)?></b><small>All WhatsApp messages</small></div><div class="wa-stat"><span>Incoming</span><b><?=number_format($incomingMessages)?></b><small>Member replies</small></div><div class="wa-stat"><span>Sent</span><b><?=number_format($sentMessages)?></b><small>Successfully sent</small></div><div class="wa-stat"><span>Bulk Status</span><b><?=getSetting('whatsapp_bulk_enabled','0')==='1'?'ON':'OFF'?></b><small>Bulk messaging control</small></div></div>
    <div class="wa-tabs"><?php if(showAdminNav('whatsapp-center')): ?><a class="<?= $tab==='home'?'active':'' ?>" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1">💬 Overview & Chat</a><?php endif; ?><?php if(showAdminNav('whatsapp-center')): ?><a class="<?= $tab==='bulk'?'active':'' ?>" href="?route=whatsapp-center&tab=bulk">📢 WhatsApp Bulk</a><?php endif; ?><?php if(showAdminNav('whatsapp-center')): ?><a class="<?= $tab==='payment'?'active':'' ?>" href="?route=whatsapp-center&tab=payment">🧾 Payment Slip</a><?php endif; ?><?php if(showAdminNav('whatsapp-center')): ?><a class="<?= $tab==='logs'?'active':'' ?>" href="?route=whatsapp-center&tab=logs">🧾 Chat Logs</a><?php endif; ?></div>

    <div id="wa-chat" data-wa-tab="home" class="wa-content" style="<?= $tab==='home'?'':'display:none' ?>">
      <?php
        $chatMessages=[];
        $chatResult=$db->query("SELECT w.*, m.code AS member_code, m.photo AS member_photo FROM whatsapp_messages w LEFT JOIN members m ON m.id=w.member_id ORDER BY w.id DESC LIMIT 500");
        while($row=$chatResult->fetchArray(SQLITE3_ASSOC)){ $chatMessages[]=$row; }
        // Query the newest 500 rows, then restore chronological order for the conversation bubbles.
        $chatMessages=array_reverse($chatMessages);
        $conversations=[]; $selectedChat=trim((string)($_GET['chat']??'')); $showChatList=(($_GET['view']??'')==='list');
        foreach($chatMessages as $row){
          $mobile=trim((string)($row['mobile']??'')); if($mobile==='') continue;
          if(!isset($conversations[$mobile])) $conversations[$mobile]=['mobile'=>$mobile,'name'=>$row['member_name']?:$mobile,'code'=>$row['member_code']??'','photo'=>$row['member_photo']??'','last'=>$row,'unread'=>0,'member_id'=>(int)($row['member_id']??0)];
          else { $conversations[$mobile]['last']=$row; if(($conversations[$mobile]['name']??'')===$mobile && !empty($row['member_name'])) $conversations[$mobile]['name']=$row['member_name']; if(empty($conversations[$mobile]['photo'])&&!empty($row['member_photo']))$conversations[$mobile]['photo']=$row['member_photo']; if(empty($conversations[$mobile]['member_id'])&&!empty($row['member_id']))$conversations[$mobile]['member_id']=(int)$row['member_id']; }
          if(($row['direction']??'')==='inbound' && in_array((string)($row['status']??''),['received','read','delivered','sent',''],true)) $conversations[$mobile]['unread']++;
        }
        uasort($conversations,function($a,$b){ return strcmp((string)($b['last']['created_at']??''),(string)($a['last']['created_at']??'')); });
        // Show registered active members in the picker even before the first inbound message.
        foreach($chatMemberRows as $chatMember){
          $digits=preg_replace('/\D+/','',(string)$chatMember['mobile']); if(strlen($digits)<10) continue;
          $mobile=(string)$chatMember['mobile'];
          if(!isset($conversations[$mobile])) $conversations[$mobile]=['mobile'=>$mobile,'name'=>$chatMember['name'],'code'=>$chatMember['code'],'photo'=>$chatMember['photo'],'last'=>['created_at'=>'','message_text'=>'Start a conversation','message_type'=>'message'],'unread'=>0,'member_id'=>(int)$chatMember['id']];
          else {$conversations[$mobile]['member_id']=(int)$chatMember['id'];$conversations[$mobile]['name']=$chatMember['name'];$conversations[$mobile]['code']=$chatMember['code'];if(empty($conversations[$mobile]['photo']))$conversations[$mobile]['photo']=$chatMember['photo'];}
        }
        if($selectedChat==='' && $conversations && !$showChatList && !$chatOnly) $selectedChat=(string)array_key_first($conversations);
        if($selectedChat!=='' && !isset($conversations[$selectedChat]) && $conversations) $selectedChat=(string)array_key_first($conversations);
        $selectedConversation=$conversations[$selectedChat]??null;
        $selectedMemberId=(int)($selectedConversation['member_id']??0);
        $selectedMessages=[];
        if($selectedChat!=='') foreach($chatMessages as $row){ if(trim((string)($row['mobile']??''))===$selectedChat) $selectedMessages[]=$row; }
      ?>
      <div class="wa-live-inbox <?=($chatOnly && $showChatList)?'show-member-list':''?>" data-has-selected="<?= $selectedConversation?'1':'0' ?>" data-has-explicit-chat="<?= trim((string)($_GET['chat']??''))!=='' ? '1' : '0' ?>">
        <aside class="wa-inbox-sidebar" id="wa-chat-list">
          <div class="wa-inbox-head">
            <div><b>Chats</b><small><?=number_format(count($conversations))?> conversations</small></div>
            <a class="btn small" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1" title="Refresh inbox">↻</a>
          </div>
          <div class="wa-inbox-search"><input type="search" id="waInboxSearch" placeholder="Search chats..." autocomplete="off"></div>
          <div class="wa-conversation-list" id="waConversationList">
            <?php if(!$conversations): ?>
              <div class="wa-empty"><div><b>No incoming chats yet</b><br><span>Meta webhook से message आने पर यहाँ conversation दिखाई देगी।</span></div></div>
            <?php else: foreach($conversations as $cv): $active=$cv['mobile']===$selectedChat; $initial=function_exists('mb_substr')?mb_strtoupper(mb_substr((string)$cv['name'],0,1)):(strtoupper(substr((string)$cv['name'],0,1))); ?>
              <a class="wa-conversation <?= $active?'active':'' ?>" data-chat-search="<?=h($cv['name'].' '.$cv['mobile'].' '.$cv['code'])?>" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1&amp;chat=<?=rawurlencode($cv['mobile'])?>">
                <div class="wa-avatar">
                  <?php if(!empty($cv['photo'])): ?><img src="<?=h(memberFileUrl($cv['photo']))?>" alt="" style="width:42px;height:42px;border-radius:50%;object-fit:cover"><?php else: ?><?=h($initial?:'W')?><?php endif; ?>
                </div>
                <div class="wa-conv-body">
                  <div class="wa-conv-top"><b><?=h($cv['name'])?></b><small><?=h(whatsappLocalTime($cv['last']['created_at']??''))?></small></div>
                  <div class="wa-conv-bottom"><span><?=h($cv['last']['message_text']?:ucfirst((string)($cv['last']['message_type']??'message')))?></span><?php if($cv['unread']>0): ?><i><?=min(99,(int)$cv['unread'])?></i><?php endif; ?></div>
                </div>
              </a>
            <?php endforeach; endif; ?>
          </div>
        </aside>
        <section class="wa-inbox-chat">
          <?php if($selectedConversation): $initial=function_exists('mb_substr')?mb_strtoupper(mb_substr((string)$selectedConversation['name'],0,1)):(strtoupper(substr((string)$selectedConversation['name'],0,1))); ?>
            <div class="wa-chat-header">
              <button class="wa-member-list-toggle" type="button" aria-label="Show member list" aria-expanded="false" onclick="toggleWaMemberList(this)"><span></span><span></span><span></span></button>
              <a class="wa-mobile-back" href="?route=whatsapp-center&amp;tab=home&amp;chat_only=1&amp;view=list#wa-chat-list" aria-label="Back to chats">‹ Chats</a>
              <div class="wa-avatar big"><?php if(!empty($selectedConversation['photo'])): ?><img src="<?=h(memberFileUrl($selectedConversation['photo']))?>" alt="" style="width:44px;height:44px;border-radius:50%;object-fit:cover"><?php else: ?><?=h($initial?:'W')?><?php endif; ?></div>
              <div><b><?=h($selectedConversation['name'])?></b><small><?=h($selectedConversation['mobile'])?><?=!empty($selectedConversation['code'])?' · '.h($selectedConversation['code']):''?></small></div>
              <span class="wa-chat-status">● WhatsApp</span>
              <a class="btn small" target="_blank" rel="noopener" href="<?=h(memberWhatsAppHref((string)$selectedConversation['mobile']))?>">Open WhatsApp</a>
               <form method="post" onsubmit="return confirm('इस chat की पूरी conversation delete करें?')"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="wa_action" value="delete_chat"><input type="hidden" name="chat_mobile" value="<?=h((string)$selectedConversation['mobile'])?>"><button class="btn small danger" type="submit">🗑️ Delete Chat</button></form>
            </div>
            <div class="wa-message-scroll" id="waMessageScroll">
              <?php if(!$selectedMessages): ?><div class="wa-empty">No messages in this chat.</div><?php endif; ?>
              <?php foreach($selectedMessages as $cm): $out=$cm['direction']==='outbound'; ?>
                <div class="wa-bubble-row <?= $out?'outbound':'inbound' ?>">
                  <div class="wa-bubble <?= $out?'out':'in' ?>">
                    <?php if(!$out && !empty($cm['member_name'])): ?><div class="wa-sender"><?=h($cm['member_name'])?></div><?php endif; ?>
                    <?php if(!empty($cm['media_file'])): ?>
                      <?php $mime=(string)($cm['media_mime']??''); $mediaUrl='?route=whatsapp-media&id='.(int)$cm['id']; ?>
                      <?php if(str_starts_with($mime,'image/')): ?><a href="<?=h($mediaUrl)?>" target="_blank"><img class="wa-media" src="<?=h($mediaUrl)?>" alt="WhatsApp image"></a>
                      <?php elseif(str_starts_with($mime,'video/')): ?><video class="wa-media" controls preload="metadata" src="<?=h($mediaUrl)?>"></video>
                      <?php elseif(str_starts_with($mime,'audio/')): ?><audio controls style="width:260px;max-width:100%;margin-top:6px" src="<?=h($mediaUrl)?>"></audio>
                      <?php else: ?><a class="btn small" target="_blank" href="<?=h($mediaUrl)?>">📎 <?=h($cm['media_name']?:'Open attachment')?></a><?php endif; ?>
                    <?php elseif(in_array((string)($cm['message_type']??''),['image','video','audio','document'],true)): ?><div class="muted">📎 <?=h(ucfirst((string)$cm['message_type']))?> attachment</div><?php endif; ?>
                    <?php if(trim((string)($cm['message_text']??''))!==''): ?><div class="wa-text"><?=nl2br(h($cm['message_text']))?></div><?php endif; ?>
                    <div class="wa-meta"><?=h(whatsappLocalTime($cm['created_at']??''))?><?php if($out): ?><span><?=h((string)($cm['status']??'sent'))?></span><?php endif; ?></div>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
            <form method="post" class="wa-compose">
              <input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="wa_action" value="send_message"><input type="hidden" name="member_id" value="<?=$selectedMemberId?>"><input type="hidden" name="chat_mobile" value="<?=h((string)$selectedConversation['mobile'])?>">
              <textarea name="message" rows="3" required placeholder="Type a WhatsApp message..." aria-label="Message"></textarea>
              <button class="btn primary" type="submit">Send</button>
            </form>
          <?php else: ?>
            <div class="wa-empty wa-chat-empty" style="height:100%"><button class="wa-member-list-toggle" type="button" aria-label="Show member list" aria-expanded="false" onclick="toggleWaMemberList(this)"><span></span><span></span><span></span></button><div><b>Select a member to chat</b><br><span>Tap the three lines to open your member list.</span></div></div>
          <?php endif; ?>
        </section>
      </div>
      <div class="wa-center-footer-note">Live Inbox uses your saved WhatsApp webhook messages. Use Refresh to check for new incoming messages; no automatic polling is used, so the page does not repeatedly hit Meta/hosting APIs.</div>
    </div>
    <script>
      function toggleWaMemberList(button){var inbox=button.closest('.wa-live-inbox');if(!inbox)return;var opening=!inbox.classList.contains('show-member-list');inbox.classList.toggle('show-member-list',opening);inbox.querySelectorAll('.wa-member-list-toggle').forEach(function(b){b.setAttribute('aria-expanded',opening?'true':'false');});}
      (function(){var area=document.querySelector('.wa-compose textarea');if(area){area.addEventListener('input',function(){this.style.height='auto';this.style.height=Math.min(this.scrollHeight,112)+'px';});}})();
    </script>
    <div id="wa-bulk" data-wa-tab="bulk" class="grid-2" style="margin-top:16px;<?= ($tab==='bulk' && showAdminNav('whatsapp-center'))?'':'display:none' ?>"><div class="panel"><div class="panel-head"><h2>📢 Bulk Message</h2><span class="badge <?=getSetting('whatsapp_bulk_enabled','0')==='1'?'success':'warning'?>"><?=getSetting('whatsapp_bulk_enabled','0')==='1'?'ON':'OFF'?></span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="wa_action" value="bulk_message"><div class="span2"><label>Message</label><textarea name="bulk_message" rows="5" placeholder="सभी active members के लिए संदेश..."></textarea></div><div><label>Maximum Members</label><input type="number" name="bulk_limit" min="1" max="100" value="50"></div><div class="span2"><button class="btn" onclick="return confirm('Selected limit तक active members को WhatsApp message भेजना है?')">📢 Start Bulk Send</button></div></form></div></div>

    <div id="wa-payment" data-wa-tab="payment" class="panel" style="margin-top:16px;<?= ($tab==='payment' && showAdminNav('whatsapp-center'))?'':'display:none' ?>">
      <div class="panel-head"><div><h2>🧾 Payment Slip</h2><small class="muted">Paid EMI और Contribution की site-generated PDF सीधे WhatsApp पर भेजें।</small></div><span class="badge info">WhatsApp Document</span></div>
      <div class="grid-2" style="margin-top:12px">
        <div class="panel"><div class="panel-head"><h3>EMI Payment Slips</h3><span class="badge success">Paid</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Member</th><th>Amount</th><th>Slip</th></tr></thead><tbody><?php while($ps=$paidEmi->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h($ps['created_at'])?></td><td><b><?=h($ps['name'])?></b><small class="block"><?=h($ps['code'])?> · EMI #<?=h((string)($ps['installment_no']??''))?></small></td><td><?=money((float)$ps['amount'])?></td><td><a class="btn small primary" target="_blank" href="?route=send-payment-slip&type=emi&id=<?=$ps['id']?>">📤 Send Slip</a></td></tr><?php endwhile; ?></tbody></table></div></div>
        <div class="panel"><div class="panel-head"><h3>Contribution Slips</h3><span class="badge success">Paid</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Member</th><th>Amount</th><th>Slip</th></tr></thead><tbody><?php while($ps=$paidContrib->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h($ps['created_at'])?></td><td><b><?=h($ps['name'])?></b><small class="block"><?=h($ps['code'])?> · <?=h($ps['month']??'')?></small></td><td><?=money((float)$ps['amount'])?></td><td><a class="btn small primary" target="_blank" href="?route=send-payment-slip&type=contribution&id=<?=$ps['id']?>">📤 Send Slip</a></td></tr><?php endwhile; ?></tbody></table></div></div>
      </div>
    </div>

    <div id="wa-auto" data-wa-tab="home" class="panel" style="margin-top:16px;<?= ($tab==='home' && showAdminNav('whatsapp-center'))?'':'display:none' ?>">
      <div class="panel-head"><div><h2>🤖 Automatic WhatsApp Messages</h2><small class="muted">हर event के लिए ON/OFF और Meta approved template name सेट करें।</small></div><span class="badge info">Controlled</span></div>
      <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="wa_action" value="save_center">
        <div><label>Welcome / ID + Password</label><select name="whatsapp_auto_welcome_enabled"><option value="1" <?=getSetting('whatsapp_auto_welcome_enabled','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_welcome_enabled','1')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Contribution Received</label><select name="whatsapp_auto_contribution_enabled"><option value="1" <?=getSetting('whatsapp_auto_contribution_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_contribution_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>EMI Payment Received</label><select name="whatsapp_auto_emi_paid_enabled"><option value="1" <?=getSetting('whatsapp_auto_emi_paid_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_emi_paid_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Loan Application</label><select name="whatsapp_auto_loan_application_enabled"><option value="1" <?=getSetting('whatsapp_auto_loan_application_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_loan_application_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Loan Approved</label><select name="whatsapp_auto_loan_approved_enabled"><option value="1" <?=getSetting('whatsapp_auto_loan_approved_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_loan_approved_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Loan Rejected</label><select name="whatsapp_auto_loan_rejected_enabled"><option value="1" <?=getSetting('whatsapp_auto_loan_rejected_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_loan_rejected_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Loan Disbursed / Created</label><select name="whatsapp_auto_loan_disbursed_enabled"><option value="1" <?=getSetting('whatsapp_auto_loan_disbursed_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_loan_disbursed_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Member Closure / Refund</label><select name="whatsapp_auto_refund_enabled"><option value="1" <?=getSetting('whatsapp_auto_refund_enabled','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_refund_enabled','1')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>EMI Reminder Control</label><select name="whatsapp_auto_emi_enabled"><option value="1" <?=getSetting('whatsapp_auto_emi_enabled','0')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_auto_emi_enabled','0')==='0'?'selected':''?>>OFF</option></select></div>
        <div><label>Staff Send Permission</label><select name="whatsapp_staff_send_enabled"><option value="1" <?=getSetting('whatsapp_staff_send_enabled','1')==='1'?'selected':''?>>Allowed</option><option value="0" <?=getSetting('whatsapp_staff_send_enabled','1')==='0'?'selected':''?>>Blocked</option></select></div>
        <div class="span2"><h3 style="margin:4px 0">Meta Template Names</h3><small class="muted">Meta Business Manager में इन्हीं names के approved templates बनाएं।</small></div>
        <div><label>Contribution Template</label><input name="whatsapp_template_contribution_name" value="<?=h(getSetting('whatsapp_template_contribution_name','contribution_received'))?>"><input name="whatsapp_template_contribution_language" value="<?=h(getSetting('whatsapp_template_contribution_language','hi'))?>"></div>
        <div><label>Loan Application Template</label><input name="whatsapp_template_loan_application_name" value="<?=h(getSetting('whatsapp_template_loan_application_name','loan_application'))?>"><input name="whatsapp_template_loan_application_language" value="<?=h(getSetting('whatsapp_template_loan_application_language','hi'))?>"></div>
        <div><label>Loan Approved Template</label><input name="whatsapp_template_loan_approved_name" value="<?=h(getSetting('whatsapp_template_loan_approved_name','loan_approved'))?>"><input name="whatsapp_template_loan_approved_language" value="<?=h(getSetting('whatsapp_template_loan_approved_language','hi'))?>"></div>
        <div><label>Loan Rejected Template</label><input name="whatsapp_template_loan_rejected_name" value="<?=h(getSetting('whatsapp_template_loan_rejected_name','loan_rejected'))?>"><input name="whatsapp_template_loan_rejected_language" value="<?=h(getSetting('whatsapp_template_loan_rejected_language','hi'))?>"></div>
        <div><label>Loan Disbursed Template</label><input name="whatsapp_template_loan_disbursed_name" value="<?=h(getSetting('whatsapp_template_loan_disbursed_name','loan_disbursed'))?>"><input name="whatsapp_template_loan_disbursed_language" value="<?=h(getSetting('whatsapp_template_loan_disbursed_language','hi'))?>"></div>
        <div><label>EMI Paid Template</label><input name="whatsapp_template_emi_paid_name" value="<?=h(getSetting('whatsapp_template_emi_paid_name','emi_payment_received'))?>"><input name="whatsapp_template_emi_paid_language" value="<?=h(getSetting('whatsapp_template_emi_paid_language','hi'))?>"></div>
        <div class="span2"><button class="btn primary">💾 Save Automation Controls</button></div>
      </form>
    </div>

    <div id="wa-logs" data-wa-tab="logs" class="panel wa-chat-logs-panel" style="margin-top:16px;<?= ($tab==='logs' && showAdminNav('whatsapp-center'))?'':'display:none' ?>"><div class="panel-head"><h2>🧾 Chat Log / Inbox</h2><span class="badge info">Webhook + Sent</span></div><div class="table-wrap wa-chat-logs-scroll"><table><thead><tr><th>Date</th><th>Member</th><th>Mobile</th><th>Direction</th><th>Type</th><th>Message</th><th>Status</th></tr></thead><tbody><?php while($w=$logs->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h(whatsappLocalTime($w['created_at']))?></td><td><?=h($w['member_name']?:($w['code']??'—'))?></td><td><?=h($w['mobile'])?></td><td><?=h($w['direction'])?></td><td><?=h($w['message_type'])?></td><td style="max-width:360px;white-space:pre-wrap"><?=h($w['message_text'])?></td><td><?=h($w['status'])?></td></tr><?php endwhile; ?></tbody></table></div></div>
    </div><?php $c=ob_get_clean(); layout('WhatsApp Center',$c); exit;
}

if($route==='whatsapp-sms-center'){
    requireRole(['admin']);
    if(!canAdmin('whatsapp-sms-center')){ http_response_code(403); exit('Access denied'); }
    $tab=in_array((string)($_GET['tab']??'meta'),['meta','sms','calls'],true)?(string)$_GET['tab']:'meta';
    $calls=$db->query("SELECT * FROM whatsapp_call_logs ORDER BY id DESC LIMIT 50");
    $totalCalls=(int)$db->querySingle("SELECT COUNT(*) FROM whatsapp_call_logs");
    $msg=''; $err='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf(); $action=(string)($_POST['settings_action']??'');
        if($action==='save_meta'){
            $keys=['whatsapp_app_id','whatsapp_app_secret','whatsapp_config_id','whatsapp_waba_id','whatsapp_business_id','whatsapp_api_key','whatsapp_phone_number_id','whatsapp_graph_version','whatsapp_webhook_verify_token','whatsapp_embedded_signup_enabled','whatsapp_embedded_signup_version','whatsapp_coexistence_enabled','whatsapp_session_logging_enabled','whatsapp_template_name','whatsapp_template_language','whatsapp_welcome_template_name','whatsapp_welcome_template_language','whatsapp_closure_template_name','whatsapp_closure_template_language'];
            foreach($keys as $k){ if(!array_key_exists($k,$_POST)) continue; $v=trim((string)$_POST[$k]); if(str_ends_with($k,'_enabled'))$v=$v==='1'?'1':'0'; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k,SQLITE3_TEXT); $st->bindValue(2,$v,SQLITE3_TEXT); $st->execute(); }
            audit('meta_connection_settings_updated','Meta WhatsApp connection settings updated'); $msg='Meta WhatsApp settings saved successfully.';
        } elseif($action==='test_meta'){
            $token=trim((string)getSetting('whatsapp_api_key','')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id','')); $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
            if($token===''||$phoneId==='') $err='Meta Access Token और Phone Number ID भरना जरूरी है।';
            elseif(!function_exists('curl_init')) $err='PHP cURL extension आवश्यक है।';
            else { $url='https://graph.facebook.com/'.rawurlencode($gv).'/'.rawurlencode($phoneId).'?fields=id,display_phone_number,verified_name,quality_rating,status'; $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>20,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token]]); $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch); $j=json_decode((string)$resp,true); if($ce||$code<200||$code>=300||!is_array($j)||isset($j['error'])) $err='Meta connection test failed'.($code?' (HTTP '.$code.')':'').($ce?': '.$ce:'').(isset($j['error']['message'])?' — '.$j['error']['message']:''); else { $msg='Meta connection OK — '.(($j['display_phone_number']??'Phone ID '.$phoneId)).' | '.(($j['verified_name']??'WhatsApp Business')); setSetting('whatsapp_embedded_last_status','Meta connection test OK on '.date('c')); audit('meta_connection_test','Meta WhatsApp connection test successful'); } }
        } elseif($action==='save_sms'){
            $keys=['sms_enabled','sms_sender_id','sms_provider','sms_api_url','sms_api_key','sms_generic_json'];
            foreach($keys as $k){ if(!array_key_exists($k,$_POST)) continue; $v=trim((string)$_POST[$k]); if($k==='sms_enabled'||$k==='sms_generic_json')$v=$v==='1'?'1':'0'; $st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"); $st->bindValue(1,$k,SQLITE3_TEXT); $st->bindValue(2,$v,SQLITE3_TEXT); $st->execute(); }
            audit('sms_settings_updated','SMS settings updated'); $msg='SMS settings saved successfully.';
        } elseif($action==='test_sms'){
            $to=trim((string)($_POST['test_sms_number']??'')); $text=trim((string)($_POST['test_sms_message']??'GS Suraha SMS test message.'));
            if($to===''||$text==='') $err='Test mobile number और message दोनों भरें।';
            elseif(getSetting('sms_enabled','1')!=='1') $err='SMS is disabled in settings.';
            else { [$ok,$info]=sendGenericSmsApi($to,$text); if($ok){$msg=$info; audit('sms_test_sent','SMS test sent to '.$to);} else $err=$info; }
        }
    }
    ob_start(); ?>
    <style>
      .wa-settings-page{font-family:Inter,Segoe UI,Arial,sans-serif;max-width:1180px;margin:0 auto}
      .wa-settings-page .wa-settings-hero{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px;padding:20px 22px;border:1px solid #dfe7f2;border-radius:20px;background:linear-gradient(135deg,#ffffff 0%,#f4f8ff 58%,#eefaf5 100%);box-shadow:0 10px 30px rgba(18,45,78,.07)}
      .wa-settings-page .wa-settings-hero h1{margin:3px 0 5px;font-size:28px;line-height:1.15;color:#14253d}
      .wa-settings-page .wa-settings-hero p{margin:0;color:#66758a;font-size:13px}
      .wa-settings-page .wa-settings-icon{width:52px;height:52px;display:grid;place-items:center;border-radius:15px;background:#e8f1ff;font-size:27px;flex:0 0 auto}
      .wa-settings-page .wa-settings-nav{display:flex;gap:9px;flex-wrap:wrap;padding:9px;margin-bottom:16px;border:1px solid #dfe6ef;border-radius:15px;background:#f7f9fc;box-shadow:0 5px 18px rgba(18,45,78,.05)}
      .wa-settings-page .wa-settings-nav a{flex:1 1 150px;display:flex;align-items:center;justify-content:center;min-height:44px;padding:9px 13px;border:1px solid #d8e1ec;border-radius:11px;background:#fff;color:#30435c;text-decoration:none;font-size:13px;font-weight:800;transition:.18s ease}
      .wa-settings-page .wa-settings-nav a:hover{border-color:#6d9ee8;transform:translateY(-1px)}
      .wa-settings-page .wa-settings-nav a.active{background:#1769d2;color:#fff;border-color:#1769d2;box-shadow:0 6px 15px rgba(23,105,210,.22)}
      .wa-settings-page .wa-card{background:#fff;border:1px solid #dfe6ef;border-radius:18px;padding:18px;box-shadow:0 8px 25px rgba(18,45,78,.06);margin-bottom:16px}
      .wa-settings-page .wa-card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
      .wa-settings-page .wa-card-head h2,.wa-settings-page .wa-card h2{margin:0;color:#172a44;font-size:18px}
      .wa-settings-page .wa-card h3{margin:0;color:#203650;font-size:15px}
      .wa-settings-page .wa-section-label{display:flex;align-items:center;gap:8px;margin:20px 0 10px;padding-bottom:8px;border-bottom:1px solid #e8edf4;color:#48617e;font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.45px}
      .wa-settings-page .settings-grid{gap:12px}
      .wa-settings-page .settings-grid>div{min-width:0}
      .wa-settings-page label{font-size:12px;font-weight:800;color:#4a5d76;margin-bottom:6px;display:block}
      .wa-settings-page input,.wa-settings-page select,.wa-settings-page textarea{width:100%;box-sizing:border-box;border:1px solid #d5dfeb;border-radius:10px;background:#fbfcfe;padding:10px 11px;color:#172a44;outline:none}
      .wa-settings-page input:focus,.wa-settings-page select:focus,.wa-settings-page textarea:focus{border-color:#5790e5;box-shadow:0 0 0 3px rgba(87,144,229,.12);background:#fff}
      .wa-settings-page .wa-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:15px;padding-top:14px;border-top:1px solid #e8edf4}
      .wa-settings-page .wa-status-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
      .wa-settings-page .wa-status-item{padding:12px 13px;border:1px solid #e2e8f0;border-radius:12px;background:#f8fafc}
      .wa-settings-page .wa-status-item span{display:block;color:#718096;font-size:11px;margin-bottom:4px}
      .wa-settings-page .wa-status-item b{display:block;color:#203650;font-size:13px;word-break:break-word}
      .wa-settings-page .wa-code{display:block;padding:12px;border:1px dashed #cfd9e6;border-radius:11px;background:#f7f9fc;color:#334e6f;font-size:11px;line-height:1.55;word-break:break-all}
      .wa-settings-page .wa-help{padding:11px 12px;border-radius:11px;background:#f4f8ff;border:1px solid #dce8fb;color:#5b6d83;font-size:12px;line-height:1.55}
      .wa-settings-page .wa-danger-help{background:#fff8f0;border-color:#f5dfbf}
      .wa-settings-page .grid-2{gap:16px}
      .wa-settings-page .table-wrap{border:1px solid #e1e7ef;border-radius:12px;overflow:auto}
      @media(max-width:700px){.wa-settings-page .wa-settings-hero{padding:16px;border-radius:16px}.wa-settings-page .wa-settings-hero h1{font-size:22px}.wa-settings-page .wa-settings-icon{width:44px;height:44px;font-size:23px}.wa-settings-page .wa-settings-nav a{flex:1 1 100%;min-height:42px}.wa-settings-page .wa-status-grid{grid-template-columns:1fr}.wa-settings-page .wa-card{padding:14px;border-radius:15px}}
    </style>
    <div class="wa-settings-page">
    <div class="wa-settings-hero"><div><div class="eyebrow">META BUSINESS MESSAGING</div><h1>⚙️ WhatsApp Settings</h1><p>Meta, SMS और Calling की सभी settings एक साफ़ और आसान जगह पर manage करें।</p></div><div class="wa-settings-icon">⚙️</div></div>
    <?php if($msg): ?><div class="alert success">✅ <?=h($msg)?></div><?php endif; ?><?php if($err): ?><div class="alert danger">⚠️ <?=h($err)?></div><?php endif; ?>
    <div class="wa-settings-nav">
      <a class="btn <?= $tab==='meta'?'primary':'' ?>" href="?route=whatsapp-sms-center&tab=meta">🔗 Meta Connection</a>
      <a class="btn <?= $tab==='sms'?'primary':'' ?>" href="?route=whatsapp-sms-center&tab=sms">📱 SMS Settings</a>
      <a class="btn <?= $tab==='calls'?'primary':'' ?>" href="?route=whatsapp-sms-center&tab=calls">📞 Calling Logs</a>
      <?php if(canAdmin('whatsapp-center')): ?><a href="?route=whatsapp-center">💬 WhatsApp Center</a><?php endif; ?>
    </div>
    <?php if($tab==='meta'): ?>
      <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="settings_action" value="save_meta">
      <div class="wa-card span2" id="waAutoConnectCard">
        <div class="wa-card-head"><h2>🔵 Automatic Meta WhatsApp Connection</h2><span class="badge <?=getSetting('whatsapp_embedded_last_status','')!==''?'success':'info'?>"><?=getSetting('whatsapp_embedded_last_status','')!==''?'Connected / Event received':'Automatic Setup'?></span></div>
        <p class="muted">Meta के official Embedded Signup से login करके WhatsApp Business account connect करें। Manual settings नीचे वैसे ही उपलब्ध रहेंगी।</p>
        <div class="settings-grid">
          <div><label>Meta App ID</label><input id="waAutoAppId" value="<?=h(getSetting('whatsapp_app_id','')?:'2161510128110351')?>" readonly></div>
          <div><label>Configuration ID</label><input id="waAutoConfigId" value="<?=h(getSetting('whatsapp_config_id','')?:'29735247966059908')?>" readonly></div>
          <div class="span2 inline-form"><button type="button" class="btn primary" id="waMetaLoginBtn" >📲 Connect WhatsApp Business App + Cloud API</button><span class="muted" id="waMetaLoginStatus"><?=h(getSetting('whatsapp_embedded_last_status','')?:'Meta Login तैयार है। पहली बार पूरा connection करने के लिए नीचे App Secret भी Save करें।')?></span></div>
        </div>
      </div>
      <script>
      (function(){
        var btn=document.getElementById('waMetaLoginBtn'); if(!btn) return;
        var status=document.getElementById('waMetaLoginStatus');
        var appId=<?=json_encode((string)(getSetting('whatsapp_app_id','')?:'2161510128110351'))?>;
        var configId=<?=json_encode((string)(getSetting('whatsapp_config_id','')?:'29735247966059908'))?>;
        var csrf=<?=json_encode(csrf())?>;
        function setStatus(t){ if(status) status.textContent=t; }
        function postSignup(data){
          var body=new URLSearchParams(); body.set('csrf',csrf); body.set('code',data.code||''); body.set('waba_id',data.waba_id||''); body.set('phone_number_id',data.phone_number_id||''); body.set('business_id',data.business_id||''); body.set('session_event',data.event||'');
          fetch('?route=whatsapp-embedded-callback',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()}).then(function(r){return r.json()}).then(function(j){setStatus(j.message||j.error||'Meta connection response received.'); if(j.connected){setTimeout(function(){location.reload()},900)}}).catch(function(e){setStatus('Connection callback failed: '+e.message)});
        }
        window.addEventListener('message',function(ev){ if(ev.origin!=='https://www.facebook.com' && ev.origin!=='https://web.facebook.com') return; if(!ev.data || ev.data.type!=='WA_EMBEDDED_SIGNUP') return; var d=ev.data.data||{}; postSignup({event:d.event||ev.data.event||'',waba_id:d.waba_id||'',phone_number_id:d.phone_number_id||'',business_id:d.business_id||''}); });
        function doLogin(){ if(!appId||!configId){setStatus('पहले Meta App ID और Configuration ID भरकर Save करें।');return;} if(!window.FB){setStatus('Meta Login SDK अभी load नहीं हुआ।');return;} setStatus('Meta login खुल रहा है…'); FB.login(function(response){ if(!response||!response.authResponse){setStatus('Meta login cancel/failed.');return;} var code=response.authResponse.code||''; if(code){postSignup({code:code,event:'LOGIN_SUCCESS'});}else{setStatus('Meta login हुआ, लेकिन authorization code नहीं मिला।');} },{config_id:configId,response_type:'code',override_default_response_type:true,extras:{version:'v4',setup:{},sessionInfoVersion:'3'}}); }
        btn.addEventListener('click',doLogin);
        window.fbAsyncInit=function(){FB.init({appId:appId,xfbml:false,version:'v26.0'});};
        if(!document.getElementById('facebook-jssdk')){var js=document.createElement('script');js.id='facebook-jssdk';js.async=true;js.defer=true;js.crossOrigin='anonymous';js.src='https://connect.facebook.net/en_US/sdk.js';document.head.appendChild(js);}
      })();
      </script>
      <div class="wa-card span2"><div class="wa-card-head"><h2>🔗 Meta WhatsApp Connection</h2><span class="badge <?=getSetting('whatsapp_api_key','')!==''&&getSetting('whatsapp_phone_number_id','')!==''?'success':'warning'?>"><?=getSetting('whatsapp_api_key','')!==''&&getSetting('whatsapp_phone_number_id','')!==''?'Configured':'Setup Required'?></span></div><p class="muted">Meta Cloud API / WhatsApp Business App Coexistence connection की पूरी settings यहाँ रखें।</p>
      <div class="settings-grid"><div><label>Meta App ID</label><input name="whatsapp_app_id" value="<?=h(getSetting('whatsapp_app_id','')?:'2161510128110351')?>"></div><div><label>App Secret</label><input type="password" name="whatsapp_app_secret" value="<?=h(getSetting('whatsapp_app_secret',''))?>"></div><div><label>Configuration ID</label><input name="whatsapp_config_id" value="<?=h(getSetting('whatsapp_config_id','')?:'29735247966059908')?>"></div><div><label>WABA ID</label><input name="whatsapp_waba_id" value="<?=h(getSetting('whatsapp_waba_id',''))?>"></div><div><label>Business ID</label><input name="whatsapp_business_id" value="<?=h(getSetting('whatsapp_business_id',''))?>"></div><div><label>Phone Number ID</label><input name="whatsapp_phone_number_id" value="<?=h(getSetting('whatsapp_phone_number_id',''))?>"></div><div class="span2"><label>Access Token</label><input type="password" name="whatsapp_api_key" value="<?=h(getSetting('whatsapp_api_key',''))?>"></div><div><label>Graph API Version</label><input name="whatsapp_graph_version" value="<?=h(getSetting('whatsapp_graph_version','v23.0'))?>"></div><div><label>Webhook Verify Token</label><input type="password" name="whatsapp_webhook_verify_token" value="<?=h(getSetting('whatsapp_webhook_verify_token',''))?>"></div><div><label>Embedded Signup</label><select name="whatsapp_embedded_signup_enabled"><option value="1" <?=getSetting('whatsapp_embedded_signup_enabled','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_embedded_signup_enabled','1')==='0'?'selected':''?>>OFF</option></select></div><div><label>Coexistence</label><select name="whatsapp_coexistence_enabled"><option value="1" <?=getSetting('whatsapp_coexistence_enabled','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_coexistence_enabled','1')==='0'?'selected':''?>>OFF</option></select></div><div><label>Session Logging</label><select name="whatsapp_session_logging_enabled"><option value="1" <?=getSetting('whatsapp_session_logging_enabled','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('whatsapp_session_logging_enabled','1')==='0'?'selected':''?>>OFF</option></select></div><div><label>Template Name</label><input name="whatsapp_template_name" value="<?=h(getSetting('whatsapp_template_name','emi_reminder_hi'))?>"></div><div><label>Template Language</label><input name="whatsapp_template_language" value="<?=h(getSetting('whatsapp_template_language','hi'))?>"></div><div><label>Welcome Template Name</label><input name="whatsapp_welcome_template_name" value="<?=h(getSetting('whatsapp_welcome_template_name','member_welcome_credentials'))?>" placeholder="Approved Meta template"></div><div><label>Welcome Template Language</label><input name="whatsapp_welcome_template_language" value="<?=h(getSetting('whatsapp_welcome_template_language','hi'))?>"></div><div><label>Closure/Refund Template Name</label><input name="whatsapp_closure_template_name" value="<?=h(getSetting('whatsapp_closure_template_name','member_closure_refund'))?>" placeholder="Approved Meta template"></div><div><label>Closure Template Language</label><input name="whatsapp_closure_template_language" value="<?=h(getSetting('whatsapp_closure_template_language','hi'))?>"></div></div>
      <div class="wa-actions"><button class="btn primary">💾 Save Meta Settings</button><button class="btn" type="submit" formaction="?route=whatsapp-sms-center&tab=meta" name="settings_action" value="test_meta">🧪 Test Meta Connection</button><a class="btn" href="?route=meta-connection">Advanced Meta Setup</a></div></div></form>
      <div class="grid-2"><div class="wa-card"><div class="wa-card-head"><h2>🧪 Meta Test Status</h2></div><div class="wa-status-grid"><div><span>Phone Number ID</span><b><?=getSetting('whatsapp_phone_number_id','')!==''?'Configured':'Missing'?></b></div><div><span>Access Token</span><b><?=getSetting('whatsapp_api_key','')!==''?'Configured':'Missing'?></b></div><div><span>Coexistence</span><b><?=getSetting('whatsapp_coexistence_enabled','1')==='1'?'ON':'OFF'?></b></div><div><span>Last Test</span><b><?=h(getSetting('whatsapp_embedded_last_status','Not tested'))?></b></div></div></div><div class="wa-card"><div class="wa-card-head"><h2>📡 Webhook</h2></div><p class="muted">Callback URL</p><code class="wa-code"><?=h(siteBaseUrl().'?route=whatsapp-call-webhook')?></code><div class="wa-help" style="margin-top:10px">Meta Developer Console में इसी URL और Verify Token को configure करें।</div></div></div>
    <?php elseif($tab==='sms'): ?>
      <form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="settings_action" value="save_sms">
      <div class="wa-card span2"><div class="wa-card-head"><h2>📱 SMS Settings</h2><span class="badge <?=getSetting('sms_enabled','1')==='1'?'success':'warning'?>"><?=getSetting('sms_enabled','1')==='1'?'Enabled':'Disabled'?></span></div><div class="settings-grid"><div><label>SMS</label><select name="sms_enabled"><option value="1" <?=getSetting('sms_enabled','1')==='1'?'selected':''?>>Enabled</option><option value="0" <?=getSetting('sms_enabled','1')==='0'?'selected':''?>>Disabled</option></select></div><div><label>Sender ID</label><input name="sms_sender_id" value="<?=h(getSetting('sms_sender_id','GSURHA'))?>"></div><div class="span2"><label>Provider</label><select name="sms_provider"><option>Manual / SMS App</option><option <?=getSetting('sms_provider')==='MSG91'?'selected':''?>>MSG91</option><option <?=getSetting('sms_provider')==='Twilio'?'selected':''?>>Twilio</option><option <?=getSetting('sms_provider')==='Generic REST API'?'selected':''?>>Generic REST API</option><option <?=getSetting('sms_provider')==='Other'?'selected':''?>>Other</option></select></div><div class="span2"><label>API URL</label><input name="sms_api_url" value="<?=h(getSetting('sms_api_url',''))?>" placeholder="https://provider.example/send"></div><div class="span2"><label>API Key / Token</label><input type="password" name="sms_api_key" value="<?=h(getSetting('sms_api_key',''))?>"></div><div><label>Generic JSON Mode</label><select name="sms_generic_json"><option value="1" <?=getSetting('sms_generic_json','1')==='1'?'selected':''?>>ON</option><option value="0" <?=getSetting('sms_generic_json','1')==='0'?'selected':''?>>OFF</option></select></div></div><div class="wa-actions"><button class="btn primary">💾 Save SMS Settings</button></div></div></form>
      <form method="post" class="wa-card"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="settings_action" value="test_sms"><div class="wa-card-head"><h2>🧪 Test SMS</h2><span class="badge info">Live provider test</span></div><div class="settings-grid"><div><label>Test Mobile Number</label><input name="test_sms_number" placeholder="919999999999" required></div><div><label>Test Message</label><input name="test_sms_message" value="GS Suraha SMS test message." required></div><div class="span2"><button class="btn primary">📤 Send Test SMS</button></div></div><p class="muted">यह button configured SMS API को real test request भेजेगा। Provider credentials खाली होने पर test नहीं भेजा जाएगा।</p></form>
    <?php else: ?>
      <div class="grid-2"><div class="wa-card"><div class="wa-card-head"><h2>📞 Calling Logs</h2><span class="badge info"><?=number_format($totalCalls)?> events</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Mobile</th><th>Type</th><th>Status</th></tr></thead><tbody><?php while($c=$calls->fetchArray(SQLITE3_ASSOC)): ?><tr><td><?=h($c['created_at'])?></td><td><?=h($c['mobile'])?></td><td><?=h($c['call_type'])?></td><td><?=h($c['call_status'])?></td></tr><?php endwhile; if($totalCalls===0): ?><tr><td colspan="4">No calling logs yet.</td></tr><?php endif; ?></tbody></table></div></div><div class="wa-card"><div class="wa-card-head"><h2>⚙️ Calling Settings</h2></div><p class="muted">Calling configuration को Meta Phone Number ID पर apply करने के लिए advanced communication settings उपलब्ध हैं।</p><a class="btn primary" href="?route=communications">Open Calling Settings</a></div></div>
    <?php endif; ?>
    </div><?php $c=ob_get_clean(); layout('WhatsApp Settings',$c); exit;
}

if($route==='communications'){
    requireRole(['admin']);$msg='';$err=''; $commView=(string)($_GET['comm_view']??'all');
    $keys=['whatsapp_enabled','member_whatsapp_otp_enabled','whatsapp_number','whatsapp_provider','whatsapp_provider_mode','whatsapp_document_enabled','whatsapp_api_url','whatsapp_api_key','whatsapp_phone_number_id','whatsapp_graph_version','whatsapp_calling_enabled','whatsapp_call_icon_visibility','whatsapp_call_callback_permission','whatsapp_call_sip_status','whatsapp_call_restrict_countries','whatsapp_webhook_verify_token','whatsapp_template_name','whatsapp_template_language','sms_enabled','sms_sender_id','sms_provider','sms_api_url','sms_api_key'];
    if($_SERVER['REQUEST_METHOD']==='POST'){
        checkCsrf();
        $action=(string)($_POST['comm_action']??'save');
        if($action==='apply_call_settings'){
            $token=trim((string)getSetting('whatsapp_api_key','')); $phoneId=preg_replace('/\D+/','',(string)getSetting('whatsapp_phone_number_id','')); $gv=trim((string)getSetting('whatsapp_graph_version','v23.0')); if($gv==='')$gv='v25.0'; if($gv[0]!=='v')$gv='v'.$gv;
            if($token===''||$phoneId===''){ $err='Meta Access Token और Phone Number ID पहले भरें।'; }
            elseif(!function_exists('curl_init')){ $err='PHP cURL extension आवश्यक है।'; }
            else {
                $countries=array_values(array_filter(array_map('trim',preg_split('/[,\n]+/',(string)($_POST['whatsapp_call_restrict_countries']??getSetting('whatsapp_call_restrict_countries',''))))));
                $payload=['calling'=>['status'=>($_POST['whatsapp_calling_enabled']??'0')==='1'?'ENABLED':'DISABLED','call_icon_visibility'=>(($_POST['whatsapp_call_icon_visibility']??'DEFAULT')==='DISABLE_ALL'?'DISABLE_ALL':'DEFAULT'),'callback_permission_status'=>(($_POST['whatsapp_call_callback_permission']??'ENABLED')==='DISABLED'?'DISABLED':'ENABLED'),'sip'=>['status'=>(($_POST['whatsapp_call_sip_status']??'DISABLED')==='ENABLED'?'ENABLED':'DISABLED')]]];
                if($countries) $payload['calling']['call_icons']=['restrict_to_user_countries'=>$countries];
                $url='https://graph.facebook.com/'.rawurlencode($gv).'/'.$phoneId.'/settings';
                $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>25,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)]); $resp=curl_exec($ch); $ce=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
                if(!$ce && $code>=200 && $code<300){ $msg='Meta Calling settings successfully updated.'; audit('whatsapp_call_settings_updated','Calling configuration applied to Phone Number ID '.$phoneId); }
                else { $detail=$ce?:$resp; $err='Meta Calling settings failed'.($code?' (HTTP '.$code.')':'').': '.$detail; }
            }
        } else {
            foreach($keys as $k){$v=trim((string)($_POST[$k]??''));$st=$db->prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");$st->bindValue(1,$k);$st->bindValue(2,$v);$st->execute();}
            audit('communication_settings_updated','WhatsApp & SMS settings updated');$msg='WhatsApp & SMS settings saved.';
        }
    }
    $wa=getSetting('whatsapp_number');$sample='Namaste, aapka GS Suraha contribution / loan update available hai.';$digits=preg_replace('/\D+/','',$wa);$waHref=$digits?'https://wa.me/'.$digits.'?text='.rawurlencode($sample):'';$smsHref=$digits?'sms:'.$digits.'?body='.rawurlencode($sample):'';
    $webhookUrl=siteBaseUrl().'?route=whatsapp-call-webhook';
    ob_start(); ?><div class="page-title"><div><div class="eyebrow">ADMIN COMMUNICATION</div><h1><?= $commView==='meta'?'🔗 Meta Connection':($commView==='sms'?'📱 SMS Settings':'WhatsApp, Calling & SMS') ?></h1><p><?= $commView==='meta'?'Meta WhatsApp API, Phone Number ID, Token, Calling और Webhook connection settings।':($commView==='sms'?'SMS provider और sender settings।':'Meta WhatsApp chat, Calling configuration और SMS settings।') ?></p></div></div><?php if($msg): ?><div class="alert success"><?=h($msg)?></div><?php endif; ?><?php if($err): ?><div class="alert danger"><?=h($err)?></div><?php endif; ?><div class="grid-2">
    <div class="panel" style="<?= $commView==='sms'?'display:none':'' ?>"><div class="panel-head"><h2>💬 WhatsApp</h2><span class="badge success">Admin Only</span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="comm_action" value="save"><div><label>WhatsApp</label><select name="whatsapp_enabled"><option value="1" <?=getSetting('whatsapp_enabled','1')==='1'?'selected':''?>>Enabled</option><option value="0" <?=getSetting('whatsapp_enabled')==='0'?'selected':''?>>Disabled</option></select></div><div><label>Member WhatsApp OTP</label><select name="member_whatsapp_otp_enabled"><option value="1" <?=getSetting('member_whatsapp_otp_enabled','1')==='1'?'selected':''?>>ON - OTP भेजें</option><option value="0" <?=getSetting('member_whatsapp_otp_enabled','1')==='0'?'selected':''?>>OFF - OTP बंद</option></select></div><div><label>Default Mobile</label><input name="whatsapp_number" value="<?=h($wa)?>" placeholder="919999999999"></div><div class="span2"><label>Provider</label><select name="whatsapp_provider"><option <?=getSetting('whatsapp_provider')==='Click to Chat'?'selected':''?>>Click to Chat</option><option <?=getSetting('whatsapp_provider')==='WhatsApp Business API'?'selected':''?>>WhatsApp Business API</option><option <?=getSetting('whatsapp_provider')==='Meta Cloud API'?'selected':''?>>Meta Cloud API</option></select></div><div><label>API Mode</label><select name="whatsapp_provider_mode"><option <?=getSetting('whatsapp_provider_mode','Meta Cloud API')==='Meta Cloud API'?'selected':''?>>Meta Cloud API</option><option <?=getSetting('whatsapp_provider_mode')==='Generic Provider API'?'selected':''?>>Generic Provider API</option></select></div><div><label>Payment Slip WhatsApp</label><select name="whatsapp_document_enabled"><option value="1" <?=getSetting('whatsapp_document_enabled','1')==='1'?'selected':''?>>Enabled - PDF attached</option><option value="0" <?=getSetting('whatsapp_document_enabled','1')==='0'?'selected':''?>>Disabled</option></select></div><div class="span2"><label>API URL (optional)</label><input name="whatsapp_api_url" value="<?=h(getSetting('whatsapp_api_url'))?>" placeholder="https://..."></div><div class="span2"><label>API Key / Token</label><input name="whatsapp_api_key" type="password" value="<?=h(getSetting('whatsapp_api_key'))?>" placeholder="Meta Access Token"></div><div><label>Meta Phone Number ID</label><input name="whatsapp_phone_number_id" value="<?=h(getSetting('whatsapp_phone_number_id'))?>"></div><div><label>Meta Graph API Version</label><input name="whatsapp_graph_version" value="<?=h(getSetting('whatsapp_graph_version','v23.0'))?>" placeholder="v23.0"></div><div><label>Hindi Template Name</label><input name="whatsapp_template_name" value="<?=h(getSetting('whatsapp_template_name','emi_reminder_hi'))?>"></div><div><label>Template Language</label><input name="whatsapp_template_language" value="<?=h(getSetting('whatsapp_template_language','hi'))?>"></div><div class="span2"><button class="btn primary">Save WhatsApp</button> <?php if($waHref): ?><a class="btn" target="_blank" rel="noopener" href="<?=h($waHref)?>">Test WhatsApp</a><?php endif; ?></div></form></div>
    <div class="panel" style="<?= $commView==='sms'?'display:none':'' ?>"><div class="panel-head"><h2>📞 Meta WhatsApp Calling</h2><span class="badge <?=getSetting('whatsapp_calling_enabled','0')==='1'?'success':'warning'?>"><?=getSetting('whatsapp_calling_enabled','0')==='1'?'Enabled':'Not configured'?></span></div><p class="muted">यह panel आपके Meta Phone Number ID पर Calling settings लागू करता है। Actual call media के लिए Meta webhook या SIP configuration आवश्यक है।</p><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="comm_action" value="apply_call_settings"><div><label>Calling</label><select name="whatsapp_calling_enabled"><option value="1" <?=getSetting('whatsapp_calling_enabled','0')==='1'?'selected':''?>>ON / ENABLED</option><option value="0" <?=getSetting('whatsapp_calling_enabled','0')==='0'?'selected':''?>>OFF / DISABLED</option></select></div><div><label>Call Button</label><select name="whatsapp_call_icon_visibility"><option value="DEFAULT" <?=getSetting('whatsapp_call_icon_visibility','DEFAULT')==='DEFAULT'?'selected':''?>>Show / DEFAULT</option><option value="DISABLE_ALL" <?=getSetting('whatsapp_call_icon_visibility')==='DISABLE_ALL'?'selected':''?>>Hide / DISABLE_ALL</option></select></div><div><label>Callback Permission</label><select name="whatsapp_call_callback_permission"><option value="ENABLED" <?=getSetting('whatsapp_call_callback_permission','ENABLED')==='ENABLED'?'selected':''?>>Enabled</option><option value="DISABLED" <?=getSetting('whatsapp_call_callback_permission')==='DISABLED'?'selected':''?>>Disabled</option></select></div><div><label>SIP</label><select name="whatsapp_call_sip_status"><option value="DISABLED" <?=getSetting('whatsapp_call_sip_status','DISABLED')==='DISABLED'?'selected':''?>>Disabled / Webhook</option><option value="ENABLED" <?=getSetting('whatsapp_call_sip_status')==='ENABLED'?'selected':''?>>Enabled / SIP</option></select></div><div class="span2"><label>Restrict to user countries (optional)</label><input name="whatsapp_call_restrict_countries" value="<?=h(getSetting('whatsapp_call_restrict_countries',''))?>" placeholder="IN,US (blank = no country restriction)"></div><div class="span2"><button class="btn primary">📞 Apply Calling Settings in Meta</button></div></form><div class="alert info"><b>Webhook URL:</b><br><code style="word-break:break-all"><?=h($webhookUrl)?></code><br><small>इसे Meta Developer → WhatsApp → Configuration/Webhooks में Callback URL के रूप में इस्तेमाल करें। Verify Token वही रखें जो नीचे A2Z में save किया गया है।</small></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="comm_action" value="save"><div class="span2"><label>Webhook Verify Token</label><input name="whatsapp_webhook_verify_token" type="password" value="<?=h(getSetting('whatsapp_webhook_verify_token',''))?>" placeholder="Create your own strong token"></div><div class="span2"><button class="btn">💾 Save Webhook Token</button></div></form></div>
    <div class="panel" style="<?= $commView==='meta'?'display:none':'' ?>"><div class="panel-head"><h2>📱 SMS</h2><span class="badge success">Admin Only</span></div><form method="post" class="settings-grid"><input type="hidden" name="csrf" value="<?=h(csrf())?>"><input type="hidden" name="comm_action" value="save"><div><label>SMS</label><select name="sms_enabled"><option value="1" <?=getSetting('sms_enabled','1')==='1'?'selected':''?>>Enabled</option><option value="0" <?=getSetting('sms_enabled')==='0'?'selected':''?>>Disabled</option></select></div><div><label>Sender ID</label><input name="sms_sender_id" value="<?=h(getSetting('sms_sender_id','GSURHA'))?>"></div><div class="span2"><label>Provider</label><select name="sms_provider"><option <?=getSetting('sms_provider')==='Manual / SMS App'?'selected':''?>>Manual / SMS App</option><option <?=getSetting('sms_provider')==='MSG91'?'selected':''?>>MSG91</option><option <?=getSetting('sms_provider')==='Twilio'?'selected':''?>>Twilio</option><option <?=getSetting('sms_provider')==='Other'?'selected':''?>>Other</option><option <?=getSetting('sms_provider')==='Generic REST API'?'selected':''?>>Generic REST API</option></select></div><div class="span2"><label>API URL (optional)</label><input name="sms_api_url" value="<?=h(getSetting('sms_api_url'))?>"></div><div class="span2"><label>API Key / Token</label><input name="sms_api_key" type="password" value="<?=h(getSetting('sms_api_key'))?>"></div><div class="span2"><button class="btn primary">Save SMS</button> <?php if($smsHref): ?><a class="btn" href="<?=h($smsHref)?>">Test SMS</a><?php endif; ?></div></form></div>
    <div class="panel" style="<?= $commView==='sms'?'display:none':'' ?>"><h2>📞 Call + 💬 Chat</h2><p class="muted">Member profile और directory में Normal Call और WhatsApp Chat buttons बने रहेंगे। WhatsApp Call button member की WhatsApp chat खोलता है; Meta Calling API की actual media/session handling webhook/SIP side पर होती है।</p><div class="rules"><div><span>Normal Phone Call</span><b>Available</b></div><div><span>WhatsApp Chat</span><b>Available</b></div><div><span>Meta Calling Settings</span><b><?=getSetting('whatsapp_calling_enabled','0')==='1'?'Configured':'Not configured'?></b></div><div><span>Webhook Endpoint</span><b>Ready</b></div></div></div>
    </div><?php $c=ob_get_clean();layout('WhatsApp, Calling & SMS',$c);exit;
}

http_response_code(404);echo 'Page not found';
?>
