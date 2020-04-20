let {TransactionHeader, Transaction, BatchHeader, Batch, BatchList} = require('sawtooth-sdk/protobuf');
let {createContext, CryptoFactory} = require('sawtooth-sdk/signing');
let {Secp256k1PrivateKey}  = require('sawtooth-sdk/signing/secp256k1');
let {createHash} = require('crypto');
let cbor = require('cbor');
const context = createContext('secp256k1');

function generatePrivateKey(hexvalue) {
  if (!hexvalue)
    hexvalue = window.crypto.getRandomValues(new Uint8Array(32));

  return new Secp256k1PrivateKey(hexvalue);
}

function getPrivateKey() {
  let privateKeyText = $("#private-key").val();
  if (!privateKeyText) {
    let privateKey = generatePrivateKey();
    privateKeyText = a2h(privateKey.asBytes());
    $("#private-key").val(privateKeyText);
  }
  return Secp256k1PrivateKey.fromHex(privateKeyText);
}

function getSigner (privateKey) {
  if (!privateKey)
    privateKey = getPrivateKey();
  return new CryptoFactory(context).newSigner(privateKey);
}

// Takes as input a payload and a signer and return a batchListBytes to send
function compileTransaction(payloadBytes, address, signer) {
  let transactionHeaderBytes = TransactionHeader.encode({
      familyName: 'cert',
      familyVersion: '1.0',
      inputs: [address],
      outputs: [address],
      signerPublicKey: signer.getPublicKey().asHex(),
      batcherPublicKey: signer.getPublicKey().asHex(),
      dependencies: [],
      payloadSha512: createHash('sha512').update(payloadBytes).digest('hex')
  }).finish()

  var signature = signer.sign(transactionHeaderBytes)

  let transaction = Transaction.create({
      header: transactionHeaderBytes,
      headerSignature: signature,
      payload: payloadBytes
  })

  let transactions = [transaction]

  let batchHeaderBytes = BatchHeader.encode({
      signerPublicKey: signer.getPublicKey().asHex(),
      transactionIds: transactions.map((txn) => txn.headerSignature),
  }).finish()

  signature = signer.sign(batchHeaderBytes)

  let batch = Batch.create({
      header: batchHeaderBytes,
      headerSignature: signature,
      transactions: transactions
  })

  let batchListBytes = BatchList.encode({
      batches: [batch]
  }).finish()

  return batchListBytes;
}

// Send a batch of transactions
function sendBatchList(batchListBytes, url, onsucces) {
  var req = new XMLHttpRequest();
  req.responseType = 'json';
  req.open("POST", url, true);
  req.setRequestHeader('Content-Type', 'application/octet-stream');
  req.onload = function (event) {
    onsucces(req.response);
  };
  r = req.send(batchListBytes);
}

// Check if the batch submission was succesful. If so calls `success` with the
// transaction data as parameter
function checkBatchSubmission(link, success, error) {
  // get the path from the existing url, and compute the complete url
  let url = getURL(link.substr(link.search('batch_statuses')));

  $.get(url, function(r){
    let status = r.data[0].status;

    if (status === 'INVALID')
      error(r.data[0].invalid_transactions[0].message);
    if (status === 'COMMITTED') {
      let batch_id = r.data[0].id;
      getTransactionInBatch(batch_id, getTransactionData, success);
    }
    if (status === 'PENDING') {
      console.log(status);
      setTimeout(function() {checkBatchSubmission(link, success, error)}, 1000);
    }
  });
}

// Get the first transaction in a given batch
function getTransactionInBatch(batch_id, callback, args) {
  let url = getURL('batches/'+batch_id);
  $.get(url, function(r) {
    let transaction_id = r.data.transactions[0].header_signature;
    callback(transaction_id, args);
  });
}

// Get the data of the given transaction. Data is passed as parameter to
// the callback
function getTransactionData(transaction_id, callback) {
  let url = getURL('transactions/'+transaction_id);
  $.get(url, function(r) {
    let transaction_data = r.data;
    callback(transaction_data);
  });
}

// Get the REST-API and Proxy form the settings and return the url
function getURL(path) {
  let api = $('#api-url').val();
  let proxy = $('#proxy-url').val();

  return proxy + api + path;
}

function getCertAddress(identifier) {
  let prefix = createHash('sha512').update(encodeUTF8('cert')).digest('hex');
  let certificate_address = createHash('sha512').update(encodeUTF8(identifier)).digest('hex');

  return prefix.substr(0,6) + certificate_address.substr(0,64);
}

function getFormData($form){
    var unindexed_array = $form.serializeArray();
    var indexed_array = {};

    $.map(unindexed_array, function(n, i){
        indexed_array[n['name']] = n['value'];
    });

    return JSON.stringify(indexed_array);
}

function encodeUTF8(string) {
  var utf8 = unescape(encodeURIComponent(string));

  var arr = [];
  for (var i = 0; i < utf8.length; i++) {
      arr.push(utf8.charCodeAt(i));
  }
  return new Uint8Array(arr);
}

function a2h (bytes) {
  let string = '';
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] < 16) string += '0';
    string += bytes[i].toString(16);
  }
  return string;
}
/*
================================================================================
================================================================================
================================Settings========================================
================================================================================
================================================================================
*/
$('#new-private-key').on('click', function(event) {
  event.preventDefault();
  let privateKey = generatePrivateKey();
  console.log(a2h(privateKey.asBytes()));
  let privateKeyText = a2h(privateKey.asBytes());
  $("#private-key").val(privateKeyText);
});
/*
================================================================================
================================================================================
============================Certificate Issue===================================
================================================================================
================================================================================
*/

function issueCertificate(callback, error_callback) {
  let action = 'create'
  let identifier = $('#issuedName').val() + $('#issuerName').val() + $('#level').val();
  let certificate = getFormData($('#issue-form'));

  let payload = action + ',' + identifier + ',' + btoa(certificate);
  let payloadBytes = cbor.encode(payload);

  console.log(payloadBytes, encodeUTF8(payloadBytes), getCertAddress(identifier));

  batchBytes = compileTransaction(payloadBytes.slice(2), getCertAddress(identifier), getSigner());

  var url = getURL('batches');

  sendBatchList(batchBytes, url, function(r) {
    checkBatchSubmission(
      r.link,
      function(data){console.log('OK', data); callback(data)},
      function(error_message){console.log('ERROR'); if (error_callback) error_callback(error_message);}
    );
  });
}

// Form binding
$('#issue-form').on('submit', function(event) {
  event.preventDefault();

  $('#issue-modal-spinner').show();
  $('#issue-modal-success').hide();
  $('#issue-modal-fail').hide();
  $('#issue-btn').prop( "disabled", true );
  $('#modal-close').prop( "disabled", true );
  $('#issue-modal').modal('open');

  issueCertificate(
    function(data){
      $('#issue-detail').val(JSON.stringify(data, null, 4));
      M.textareaAutoResize($('#issue-detail'));
      $('#issue-modal-success').show();
      $('#issue-modal-fail').hide();
      $('#issue-modal-spinner').hide();
      $('#issue-modal-text').show();
      $('#modal-close').prop("disabled", false);
    },
    function(error_message) {
      if (error_message.search("Certificate already exists") > -1)
        $('#issue-error-detail').val("The certificate for the same student is already stored");
      else
        $('#issue-error-detail').val(error_message);
      M.textareaAutoResize($('#issue-error-detail'));
      $('#issue-modal-success').hide();
      $('#issue-modal-fail').show();
      $('#issue-modal-spinner').hide();
      $('#issue-modal-text').show();
      $('#modal-close').prop("disabled", false);
    });

});


/*
================================================================================
================================================================================
============================Certificate List====================================
================================================================================
================================================================================
*/
function verifyTransaction(trustedKeys, publicKey, name) {
  if (publicKey in trustedKeys && trustedKeys[publicKey] == name)
    return true;
  else
    return false;
}

function refreshTransactionList() {
  // Load trusted Keys
  let trustedKeys = {};
  try {
    trustedKeys = JSON.parse($("#trusted-keys").val());
  }
  catch {
    M.toast({html: 'Error while parsing the trusted keys. Please fix your settings'})
  }

  // Remove existing rows
  $("#tbody-list tr").remove();

  // Remove existing modals
  $("#cert-detail-modals div").remove();

  let url = getURL('transactions');
  $.get(url, function(data) {
    for (transaction of data.data) {
      if (transaction.header.family_name == "cert") {
        let pub_key = transaction.header.batcher_public_key;

        let payload = atob(transaction.payload);
        let certificate = JSON.parse(atob(payload.split(',')[2]));
        let transaction_text = JSON.stringify(transaction, null, 4);

        let id = "modal-detail-" + transaction.header_signature;

        let verified = verifyTransaction(trustedKeys, pub_key, certificate.issuerName);

        let row = "<tr>" +
                  "<td>" + certificate.issuedName + "</td>" +
                  "<td>" + certificate.certificateName + "</td>" +
                  "<td>" + certificate.dateIssued + "</td>" +
                  "<td>" + certificate.dateExpired + "</td>" +
                  "<td>" + (certificate.level == 1 ? "Bachelor" : certificate.level == 2 ? "Master" : "PHD") + "</td>" +
                  "<td>" + certificate.issuerName + "</td>" +
                  "<td><i class=\"material-icons\">" + (verified ? "done" : "close") + "</i></td>" +
                  "<td class=\"right\"><button class=\"btn-floating orange waves-effect waves-light modal-trigger\" data-target=\"" + id + "\"><i class=\"material-icons\">add</i></button></td>" +
                  "</tr>";
        $("#tbody-list").append(row);

        let modal = "<div id=\"" + id + "\" class=\"modal\">" +
                      "<div class=\"modal-content\">" +
                        "<h4>Transaction Details</h4>" +
                        "<div>" +
                          "<textarea class=\"materialize-textarea\" readonly></textarea>" +
                          "<label for=\"textarea1\">Transaction detail</label>" +
                      "</div>" +
                      "</div>" +
                    "</div>";

        $("#cert-detail-modals").append(modal);
        $("#" + id + " textarea").val(transaction_text);
        M.textareaAutoResize($("#" + id + " textarea"));

        $("#" + id).modal();
      }
    }
  });
}

// Button binding
$('#refresh-list').on('click', function() {
  refreshTransactionList();
});
