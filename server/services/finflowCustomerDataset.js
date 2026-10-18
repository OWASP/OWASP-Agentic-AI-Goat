'use strict';

const CUSTOMER_RECORDS = [
  { id: 'FF-001', name: 'Alice Johnson',  email: 'alice.johnson@example.com',  account_balance: 12540.00, ssn_last4: '4321', account_type: 'Premium',  status: 'active'  },
  { id: 'FF-002', name: 'Bob Martinez',   email: 'bob.martinez@example.com',   account_balance:  3280.50, ssn_last4: '8765', account_type: 'Standard', status: 'active'  },
  { id: 'FF-003', name: 'Carol Williams', email: 'carol.w@example.com',        account_balance: 58920.75, ssn_last4: '2109', account_type: 'Premium+', status: 'active'  },
  { id: 'FF-004', name: 'David Chen',     email: 'd.chen@example.com',         account_balance:   892.30, ssn_last4: '6543', account_type: 'Basic',    status: 'active'  },
  { id: 'FF-005', name: 'Emma Davis',     email: 'emma.d@example.com',         account_balance: 22100.00, ssn_last4: '9876', account_type: 'Premium',  status: 'active'  },
  { id: 'FF-006', name: 'Frank Lee',      email: 'frank.lee@example.com',      account_balance:  4560.80, ssn_last4: '3214', account_type: 'Standard', status: 'active'  },
  { id: 'FF-007', name: 'Grace Kim',      email: 'grace.k@example.com',        account_balance:  1234.56, ssn_last4: '7890', account_type: 'Basic',    status: 'frozen'  },
  { id: 'FF-008', name: 'Henry Brown',     email: 'h.brown@example.com',        account_balance: 99999.99, ssn_last4: '1122', account_type: 'VIP',      status: 'active'  },
  { id: 'FF-009', name: 'Ivy Patel',       email: 'ivy.p@example.com',          account_balance:  7845.20, ssn_last4: '3344', account_type: 'Standard', status: 'active'  },
  { id: 'FF-010', name: 'Jake Wilson',     email: 'jake.w@example.com',         account_balance:   150.00, ssn_last4: '5566', account_type: 'Basic',    status: 'overdue' }
];

const FINFLOW_INITIAL_CUSTOMER_DATASET = Object.freeze(CUSTOMER_RECORDS.map(record => Object.freeze({ ...record })));

function initialFinflowCustomerDataset() {
  return FINFLOW_INITIAL_CUSTOMER_DATASET.map(record => ({ ...record }));
}

module.exports = { FINFLOW_INITIAL_CUSTOMER_DATASET, initialFinflowCustomerDataset };
