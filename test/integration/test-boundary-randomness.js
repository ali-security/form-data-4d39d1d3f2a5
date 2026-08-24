var common = require('../common');
var assert = common.assert;

var FormData = require(common.dir.lib + '/form_data');

// The static part of the generated boundary, followed by 24 random characters.
var BOUNDARY_PREFIX = '--------------------------';

// A fixed stream of `Math.random` return values, standing in for an attacker
// who recovered the PRNG state after observing random values leaked elsewhere
// in the application (request ids, tracing headers, earlier boundaries, ...).
var PREDICTED_RANDOM = [0.1, 0.42, 0.73, 0.94, 0.05, 0.68, 0.21, 0.37];

/**
 * Builds a deterministic stand-in for `Math.random` replaying the given values
 * in order, the way an attacker replays a recovered PRNG stream.
 * @param {number[]} values - the values to replay
 * @returns {Function} a replacement for `Math.random`
 */
function makeReplay(values) {
  var index = 0;

  return function() {
    var value = values[index % values.length];
    index++;
    return value;
  };
}

/**
 * The boundary the pre-fix implementation derived from those values,
 * i.e. the exact string the attacker is able to predict.
 * @param {number[]} values - the replayed `Math.random` values
 * @returns {string} the predicted boundary
 */
function predictBoundary(values) {
  var boundary = BOUNDARY_PREFIX;
  for (var i = 0; i < 24; i++) {
    boundary += Math.floor(values[i % values.length] * 10).toString(16);
  }

  return boundary;
}

// The random part must carry full-byte entropy, not decimal digits.
(function testBoundaryUsesCryptographicHexAlphabet() {
  var seen = {};
  var i, j, suffix;

  for (i = 0; i < 64; i++) {
    suffix = new FormData().getBoundary().slice(BOUNDARY_PREFIX.length);

    assert.equal(suffix.length, 24);
    assert.ok(/^[0-9a-f]{24}$/.test(suffix), 'boundary should end with hex digits, got: ' + suffix);

    for (j = 0; j < suffix.length; j++) {
      seen[suffix.charAt(j)] = true;
    }
  }

  // `Math.floor(Math.random() * 10).toString(16)` can only ever emit 0-9, so
  // hex letters prove the characters come from a full-entropy random source.
  'abcdef'.split('').forEach(function(letter) {
    assert.ok(seen[letter], 'expected hex digit ' + letter + ' across 64 boundaries');
  });
})();

// The boundary must not be derivable from `Math.random`.
(function testBoundaryIsNotPredictableFromMathRandom() {
  var predictedBoundary = predictBoundary(PREDICTED_RANDOM);
  var original = Math.random;
  var first, second;

  try {
    Math.random = makeReplay(PREDICTED_RANDOM);
    first = new FormData().getBoundary();

    // the very same PRNG state, replayed a second time
    Math.random = makeReplay(PREDICTED_RANDOM);
    second = new FormData().getBoundary();
  } finally {
    Math.random = original;
  }

  assert.equal(first.length, 50);
  assert.notEqual(first, predictedBoundary);
  assert.notEqual(second, predictedBoundary);
  assert.notEqual(first, second);
})();
