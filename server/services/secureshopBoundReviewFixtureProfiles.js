'use strict';

// Immutable workload profiles. The legacy profile is a compatibility artifact:
// do not regenerate it from mutable commerce seed data.
const crypto = require('node:crypto');

function freezeProfile(rows) {
  return Object.freeze(rows.map(row => Object.freeze({ ...row })));
}
function digestProfile(rows) {
  return crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex');
}

const PREFERRED_REVIEW_FIXTURES = freezeProfile([
  {
    "productId": 79,
    "authorId": 8,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 21,
    "authorId": 7,
    "body": "Buy our unrelated casino advertising package! Visit https://ads.example.test for a promotional subscription.",
    "rating": 5
  }
]);
const LEGACY_REVIEW_FIXTURES = freezeProfile([
  {
    "productId": 53,
    "authorId": 4,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 4
  },
  {
    "productId": 21,
    "authorId": 7,
    "body": "Not perfect but the value is there.",
    "rating": 4
  },
  {
    "productId": 79,
    "authorId": 8,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 13,
    "authorId": 8,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 2
  },
  {
    "productId": 109,
    "authorId": 1,
    "body": "Fine. Nothing to write home about — but that's a compliment given the price.",
    "rating": 3
  },
  {
    "productId": 76,
    "authorId": 4,
    "body": "Not perfect but the value is there.",
    "rating": 4
  },
  {
    "productId": 55,
    "authorId": 1,
    "body": "The colour is even nicer in person.",
    "rating": 4
  },
  {
    "productId": 69,
    "authorId": 4,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 4
  },
  {
    "productId": 68,
    "authorId": 4,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 5
  },
  {
    "productId": 26,
    "authorId": 1,
    "body": "Not what I expected from the photos.",
    "rating": 1
  },
  {
    "productId": 28,
    "authorId": 4,
    "body": "Arrived damaged. Support was slow.",
    "rating": 1
  },
  {
    "productId": 71,
    "authorId": 4,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 5
  },
  {
    "productId": 116,
    "authorId": 8,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 4
  },
  {
    "productId": 67,
    "authorId": 7,
    "body": "One month in and the finish is already chipping.",
    "rating": 1
  },
  {
    "productId": 23,
    "authorId": 1,
    "body": "The colour is even nicer in person.",
    "rating": 4
  },
  {
    "productId": 66,
    "authorId": 1,
    "body": "One month in and the finish is already chipping.",
    "rating": 1
  },
  {
    "productId": 110,
    "authorId": 1,
    "body": "Arrived damaged. Support was slow.",
    "rating": 1
  },
  {
    "productId": 16,
    "authorId": 8,
    "body": "Genuinely delighted with this. Better than I expected.",
    "rating": 4
  },
  {
    "productId": 75,
    "authorId": 1,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 5
  },
  {
    "productId": 97,
    "authorId": 4,
    "body": "Runs hot after 2 hours. Otherwise nothing to report.",
    "rating": 3
  },
  {
    "productId": 63,
    "authorId": 8,
    "body": "Genuinely delighted with this. Better than I expected.",
    "rating": 4
  },
  {
    "productId": 122,
    "authorId": 8,
    "body": "The colour is even nicer in person.",
    "rating": 5
  },
  {
    "productId": 42,
    "authorId": 8,
    "body": "One month in and the finish is already chipping.",
    "rating": 2
  },
  {
    "productId": 1,
    "authorId": 4,
    "body": "Some rough edges but I can see the intent.",
    "rating": 3
  },
  {
    "productId": 30,
    "authorId": 7,
    "body": "Wife loved it. Now she wants another one.",
    "rating": 5
  },
  {
    "productId": 120,
    "authorId": 7,
    "body": "Not what I expected from the photos.",
    "rating": 1
  },
  {
    "productId": 106,
    "authorId": 1,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 4
  },
  {
    "productId": 91,
    "authorId": 7,
    "body": "Genuinely delighted with this. Better than I expected.",
    "rating": 4
  },
  {
    "productId": 121,
    "authorId": 8,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 4
  },
  {
    "productId": 97,
    "authorId": 7,
    "body": "Not what I expected from the photos.",
    "rating": 1
  },
  {
    "productId": 15,
    "authorId": 1,
    "body": "Great in theory, average in practice. It works.",
    "rating": 3
  },
  {
    "productId": 36,
    "authorId": 1,
    "body": "Wife loved it. Now she wants another one.",
    "rating": 4
  },
  {
    "productId": 27,
    "authorId": 7,
    "body": "Wife loved it. Now she wants another one.",
    "rating": 5
  },
  {
    "productId": 88,
    "authorId": 4,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 13,
    "authorId": 4,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 102,
    "authorId": 4,
    "body": "Great in theory, average in practice. It works.",
    "rating": 3
  },
  {
    "productId": 12,
    "authorId": 1,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 2
  },
  {
    "productId": 114,
    "authorId": 1,
    "body": "Arrived damaged. Support was slow.",
    "rating": 1
  },
  {
    "productId": 39,
    "authorId": 7,
    "body": "Arrived damaged. Support was slow.",
    "rating": 2
  },
  {
    "productId": 113,
    "authorId": 7,
    "body": "Not perfect but the value is there.",
    "rating": 5
  },
  {
    "productId": 11,
    "authorId": 1,
    "body": "Runs hot after 2 hours. Otherwise nothing to report.",
    "rating": 3
  },
  {
    "productId": 79,
    "authorId": 1,
    "body": "Not what I expected from the photos.",
    "rating": 2
  },
  {
    "productId": 28,
    "authorId": 1,
    "body": "Not what I expected from the photos.",
    "rating": 1
  },
  {
    "productId": 34,
    "authorId": 4,
    "body": "One month in and the finish is already chipping.",
    "rating": 2
  },
  {
    "productId": 119,
    "authorId": 8,
    "body": "Not perfect but the value is there.",
    "rating": 4
  },
  {
    "productId": 23,
    "authorId": 4,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 5
  },
  {
    "productId": 5,
    "authorId": 4,
    "body": "Not perfect but the value is there.",
    "rating": 4
  },
  {
    "productId": 103,
    "authorId": 1,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 96,
    "authorId": 7,
    "body": "One month in and the finish is already chipping.",
    "rating": 1
  },
  {
    "productId": 103,
    "authorId": 1,
    "body": "Fine. Nothing to write home about — but that's a compliment given the price.",
    "rating": 3
  },
  {
    "productId": 99,
    "authorId": 8,
    "body": "One month in and the finish is already chipping.",
    "rating": 1
  },
  {
    "productId": 112,
    "authorId": 4,
    "body": "Not what I expected from the photos.",
    "rating": 1
  },
  {
    "productId": 16,
    "authorId": 8,
    "body": "Small footprint, big impact. Would buy again.",
    "rating": 5
  },
  {
    "productId": 115,
    "authorId": 1,
    "body": "Arrived damaged. Support was slow.",
    "rating": 1
  },
  {
    "productId": 65,
    "authorId": 1,
    "body": "Genuinely delighted with this. Better than I expected.",
    "rating": 4
  },
  {
    "productId": 51,
    "authorId": 1,
    "body": "Great in theory, average in practice. It works.",
    "rating": 3
  },
  {
    "productId": 47,
    "authorId": 8,
    "body": "Arrived damaged. Support was slow.",
    "rating": 2
  },
  {
    "productId": 95,
    "authorId": 4,
    "body": "The colour is even nicer in person.",
    "rating": 5
  },
  {
    "productId": 90,
    "authorId": 4,
    "body": "Arrived damaged. Support was slow.",
    "rating": 2
  },
  {
    "productId": 93,
    "authorId": 4,
    "body": "Wife loved it. Now she wants another one.",
    "rating": 5
  },
  {
    "productId": 50,
    "authorId": 8,
    "body": "Not perfect but the value is there.",
    "rating": 5
  },
  {
    "productId": 116,
    "authorId": 4,
    "body": "Genuinely delighted with this. Better than I expected.",
    "rating": 5
  },
  {
    "productId": 118,
    "authorId": 4,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 103,
    "authorId": 7,
    "body": "Louder than advertised. Would not recommend for bedroom use.",
    "rating": 1
  },
  {
    "productId": 54,
    "authorId": 7,
    "body": "Exactly what the listing described. Fast shipping.",
    "rating": 5
  },
  {
    "productId": 53,
    "authorId": 7,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 5
  },
  {
    "productId": 107,
    "authorId": 1,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 4
  },
  {
    "productId": 73,
    "authorId": 1,
    "body": "Some rough edges but I can see the intent.",
    "rating": 3
  },
  {
    "productId": 49,
    "authorId": 4,
    "body": "Fine. Nothing to write home about — but that's a compliment given the price.",
    "rating": 3
  },
  {
    "productId": 52,
    "authorId": 8,
    "body": "Small footprint, big impact. Would buy again.",
    "rating": 5
  },
  {
    "productId": 107,
    "authorId": 7,
    "body": "Runs hot after 2 hours. Otherwise nothing to report.",
    "rating": 3
  },
  {
    "productId": 72,
    "authorId": 8,
    "body": "One month in and the finish is already chipping.",
    "rating": 2
  },
  {
    "productId": 46,
    "authorId": 7,
    "body": "Not perfect but the value is there.",
    "rating": 5
  },
  {
    "productId": 51,
    "authorId": 1,
    "body": "Solid build quality. Feels like it will last.",
    "rating": 4
  }
]);
const PROFILE_DIGESTS = Object.freeze({
  preferred: '28b74f09b6c9ee9ccc0bfbfbe8c40c40dd1885d9339b854b9f2b9f203644298d',
  legacy: '4a1e5c64312049ade550bd6d5c8c5e7782dc17ab7308d58ef2968b063b3b3d46',
});

if (digestProfile(PREFERRED_REVIEW_FIXTURES) !== PROFILE_DIGESTS.preferred
    || digestProfile(LEGACY_REVIEW_FIXTURES) !== PROFILE_DIGESTS.legacy) {
  throw new Error('SecureShop review fixture profile integrity check failed');
}

module.exports = Object.freeze({ PREFERRED_REVIEW_FIXTURES, LEGACY_REVIEW_FIXTURES,
  PROFILE_DIGESTS, digestProfile });

