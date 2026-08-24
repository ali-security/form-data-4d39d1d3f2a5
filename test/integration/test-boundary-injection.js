var common = require('../common');
var assert = common.assert;
var http = require('http');
var IncomingForm = require('formidable').IncomingForm;

var FormData = require(common.dir.lib + '/form_data');

// The static part of the generated boundary, followed by 24 random characters.
var BOUNDARY_PREFIX = '--------------------------';

// A fixed stream of `Math.random` return values, standing in for an attacker
// who recovered the PRNG state after observing random values leaked elsewhere
// in the application (request ids, tracing headers, earlier boundaries, ...).
var PREDICTED_RANDOM = [0.1, 0.42, 0.73, 0.94, 0.05, 0.68, 0.21, 0.37];

var INJECTED_FIELD = 'isAdmin';

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

var predictedBoundary = predictBoundary(PREDICTED_RANDOM);

// Attacker controlled field content carrying a forged part, delimited with the
// boundary the attacker predicted from the `Math.random` stream.
var attackerValue = 'harmless'
  + FormData.LINE_BREAK + '--' + predictedBoundary + FormData.LINE_BREAK
  + 'Content-Disposition: form-data; name="' + INJECTED_FIELD + '"' + FormData.LINE_BREAK
  + FormData.LINE_BREAK
  + 'true';

var parsedFields = {};
var requestParsed = false;

var server = http.createServer(function(req, res) {
  var incomingForm = new IncomingForm();

  incomingForm.parse(req);

  incomingForm
    .on('field', function(name, value) {
      parsedFields[name] = value;
    })
    .on('end', function() {
      requestParsed = true;
      common.actions.formOnEnd(res);
    });
});

server.listen(common.port, function() {
  var form = new FormData();
  var original = Math.random;

  try {
    // the form is built while the attacker owns the `Math.random` stream
    Math.random = makeReplay(PREDICTED_RANDOM);
    form.append('my_field', attackerValue);
    form.getBoundary();
  } finally {
    Math.random = original;
  }

  common.actions.submit(form, server);
});

process.on('exit', function() {
  assert.ok(requestParsed, 'the form should have been submitted and parsed');
  assert.deepEqual(Object.keys(parsedFields), ['my_field']);
  assert.equal(INJECTED_FIELD in parsedFields, false, 'the forged part should not become a field');
  assert.ok(parsedFields.my_field.indexOf(predictedBoundary) !== -1, 'the forged part should stay inside the field value');
});
