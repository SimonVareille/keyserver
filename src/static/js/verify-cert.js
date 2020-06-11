/* eslint-disable */

;(function($) {
  'use strict';

  // POST signatures form
  $('#signatures form').submit(function(e) {
    e.preventDefault();
    $('#signatures .alert').addClass('hidden');
    var elements = $('#signatures form')[0];
    var obj = {sig: []};
    for(var elem of elements){
      switch(elem.name) {
        case "op":
        case "keyId":
        case "nonce":
          obj[elem.name] = elem.value;
          break;
        case "sig":
          if(elem.checked)
            obj["sig"].push(elem.value);
          break;
      }
    }
    $.ajax({
      method: 'POST',
      url: '/api/v1/key',
      data: JSON.stringify(obj),
      contentType: 'application/json',
    }).done(function(data, textStatus, xhr) {
      if (xhr.status === 304) {
        alert('signatures', 'danger', 'Key already exists!');
      } else {
        alert('signatures', 'success', xhr.responseText);
      }
    })
    .fail(function(xhr) {
      alert('signatures', 'danger', xhr.responseText);
    });
  });

  function alert(region, outcome, text) {
    $('#' + region + ' .alert-' + outcome + ' span').html(text);
    $('#' + region + ' .alert-' + outcome).removeClass('hidden');
  }

}(jQuery));
