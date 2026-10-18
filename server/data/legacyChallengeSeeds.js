'use strict';
module.exports={products:[
    ['Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', '/images/laptop.jpg'],
    ['Smartphone X', 'Latest smartphone with AI features', 899.99, 'Electronics', '/images/phone.jpg'],
    ['Coffee Maker', 'Smart coffee maker with app control', 199.99, 'Appliances', '/images/coffee.jpg'],
    ['Gaming Chair', 'Ergonomic gaming chair with RGB lighting', 299.99, 'Furniture', '/images/chair.jpg'],
    ['Wireless Headphones', 'Noise-cancelling wireless headphones', 249.99, 'Electronics', '/images/headphones.jpg']
  ],comments:[
    [1, 'Great product! Highly recommended.'],
    [2, 'Good value for money.'],
    [1, '<script>alert("XSS Vulnerability!")</script>This comment contains XSS'],
    [2, 'The delivery was fast and packaging was excellent.']
  ]};
