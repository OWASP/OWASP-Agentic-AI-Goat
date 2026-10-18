CREATE SCHEMA aria;
REVOKE ALL ON SCHEMA aria FROM PUBLIC;
CREATE TABLE aria.seed_state (version integer PRIMARY KEY);
CREATE TABLE aria.products (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 product_id text UNIQUE NOT NULL, name text NOT NULL, category text NOT NULL,
 price double precision NOT NULL, description text, stock integer DEFAULT 100, available integer DEFAULT 1
);
CREATE TABLE aria.orders (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, order_number text UNIQUE NOT NULL,
 user_id text NOT NULL, product_name text NOT NULL, quantity integer DEFAULT 1,
 unit_price double precision, total_amount double precision, shipping_address text,
 status text DEFAULT 'pending', payment_method text DEFAULT 'credit_card', created_at timestamptz DEFAULT now()
);
CREATE INDEX orders_user ON aria.orders(user_id);
CREATE TABLE aria.receipts (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, order_number text NOT NULL REFERENCES aria.orders(order_number),
 receipt_number text UNIQUE NOT NULL, amount double precision,
 payment_method text DEFAULT 'credit_card', issued_at timestamptz DEFAULT now()
);
CREATE TABLE aria.cart (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id text NOT NULL,
 product_name text NOT NULL, quantity integer DEFAULT 1, unit_price double precision,
 added_at timestamptz DEFAULT now(), UNIQUE(user_id, product_name)
);
CREATE TABLE aria.chat_history (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id text NOT NULL,
 message_type text NOT NULL, message text NOT NULL, timestamp timestamptz DEFAULT now()
);
CREATE INDEX history_user ON aria.chat_history(user_id, id);
GRANT USAGE ON SCHEMA aria TO dvaia_aria_runtime;
GRANT SELECT ON aria.products TO dvaia_aria_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON aria.orders, aria.receipts, aria.cart, aria.chat_history TO dvaia_aria_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA aria TO dvaia_aria_runtime;
