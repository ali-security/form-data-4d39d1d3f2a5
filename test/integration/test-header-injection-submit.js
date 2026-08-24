/*
CVE-2026-12143: an attacker controlled field name or filename must not be able to
terminate its header line and have a downstream multipart parser accept forged
headers or entire smuggled parts.
*/

var common = require('../common');
var assert = common.assert;
var http = require('http');
var IncomingForm = require('formidable').IncomingForm;

var FormData = require(common.dir.lib + '/form_data');

var form = new FormData();
var boundary = form.getBoundary();

// A field name that closes the `name="` parameter, ends the header block, supplies
// a value for the legitimate field, and then opens a whole forged `is_admin` part.
var smuggledFieldName = 'username"'
  + FormData.LINE_BREAK + FormData.LINE_BREAK
  + 'legit_user' + FormData.LINE_BREAK
  + '--' + boundary + FormData.LINE_BREAK
  + 'Content-Disposition: form-data; name="is_admin"' + FormData.LINE_BREAK
  + FormData.LINE_BREAK
  + 'true' + FormData.LINE_BREAK
  + '--' + boundary + FormData.LINE_BREAK
  + 'Content-Disposition: form-data; name="swallowed';

// A filename that closes the `filename="` parameter, injects an extra header line
// and then smuggles a second forged `uploaded_by` part.
var smuggledFilename = 'a"'
  + FormData.LINE_BREAK + 'X-Injected: yes'
  + FormData.LINE_BREAK + FormData.LINE_BREAK
  + 'file_body' + FormData.LINE_BREAK
  + '--' + boundary + FormData.LINE_BREAK
  + 'Content-Disposition: form-data; name="uploaded_by"' + FormData.LINE_BREAK
  + FormData.LINE_BREAK
  + 'attacker' + FormData.LINE_BREAK
  + '--' + boundary + FormData.LINE_BREAK
  + 'Content-Disposition: form-data; name="swallowed_too"; filename="b';

var parsedFields = {};
var parsedFiles = {};
var requestParsed = false;

var server = http.createServer(function(req, res) {
  var incomingForm = new IncomingForm({uploadDir: common.dir.tmp});

  incomingForm.parse(req);

  incomingForm
    .on('field', function(name, value) {
      parsedFields[name] = value;
    })
    .on('file', function(name, file) {
      parsedFiles[name] = file;
    })
    .on('end', function() {
      requestParsed = true;
      common.actions.formOnEnd(res);
    });
});

server.listen(common.port, function() {
  form.append(smuggledFieldName, 'ignored_value');
  form.append('attachment', Buffer.from('payload'), {filename: smuggledFilename});

  common.actions.submit(form, server);
});

process.on('exit', function() {
  assert.ok(requestParsed, 'the form should have been submitted and parsed');

  assert.equal('is_admin' in parsedFields, false, 'a CRLF-laden field name must not smuggle an extra field');
  assert.equal('uploaded_by' in parsedFields, false, 'a CRLF-laden filename must not smuggle an extra field');
  assert.equal(Object.keys(parsedFields).length, 1, 'the forged part must stay inside the escaped field name, so only one field arrives');

  assert.equal('swallowed_too' in parsedFiles, false, 'a CRLF-laden filename must not smuggle an extra part');
  assert.deepEqual(Object.keys(parsedFiles), ['attachment'], 'only the intended file part should arrive');
});
