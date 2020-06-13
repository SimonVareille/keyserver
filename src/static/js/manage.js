/* eslint-disable */

;(function($) {
  'use strict';

  $('.progress-bar').css('width', '100%');

  // POST key form
  $('#addKey form').submit(function(e) {
    e.preventDefault();
    $('#addKey .alert').addClass('hidden');
    $('#addKey .progress').removeClass('hidden');
    $.ajax({
      method: 'POST',
      url: '/api/v1/key',
      data: JSON.stringify({ publicKeyArmored:$('#addKey textarea').val() }),
      contentType: 'application/json',
    }).done(function(data, textStatus, xhr) {
      if (xhr.status === 304) {
        alert('addKey', 'danger', 'Key already exists!');
      } else {
        alert('addKey', 'success', xhr.responseText);
      }
    })
    .fail(function(xhr) {
      alert('addKey', 'danger', xhr.responseText);
    });
  });

  // DELETE key form
  $('#removeKey form').submit(function(e) {
    e.preventDefault();
    $('#removeKey .alert').addClass('hidden');
    $('#removeKey .progress').removeClass('hidden');
    var email = $('#removeKey input[type="email"]').val();
    $.ajax({
      method: 'DELETE',
      url: '/api/v1/key?email=' + encodeURIComponent(email)
    }).done(function(data, textStatus, xhr) {
      alert('removeKey', 'success', xhr.responseText);
    })
    .fail(function(xhr) {
      alert('removeKey', 'danger', xhr.responseText);
    });
  });

  function alert(region, outcome, text) {
    $('#' + region + ' .progress').addClass('hidden');
    $('#' + region + ' .alert-' + outcome + ' span').text(text);
    $('#' + region + ' .alert-' + outcome).removeClass('hidden');
  }
  
  $('#drop_zone').on('drop',
    function(ev) {
      // Prevent default behavior (Prevent file from being opened)
      ev.stopPropagation();
      ev.preventDefault();
      $('#addKey .alert').addClass('hidden');
      if(ev.originalEvent.dataTransfer.files[0].type != "text/plain") {
        alert('addKey', 'danger', 'You must import an ascii-armored key file!');
        return;
      }      
      handleFiles(ev.originalEvent.dataTransfer.files);
  });
  $('#drop_zone').on('dragover', 
    function(ev) {
      // Prevent default behavior (Prevent file from being opened)
      ev.stopPropagation();
      ev.preventDefault();
      ev.originalEvent.dataTransfer.dropEffect = 'copy';
  });
  $('#drop_zone').on('dragenter', 
    function(ev) {
      // Prevent default behavior (Prevent file from being opened)
      ev.stopPropagation();
      ev.preventDefault();
      ev.originalEvent.dataTransfer.dropEffect = 'copy';
  });

  $('#fileSelect').click(function() {
    $('#file-selector').click();
  });

  $('#file-selector').change(function() {
    $('#addKey .alert').addClass('hidden');
    handleFiles(this.files);
  });
  
  function handleFiles(files) {
    if(files.length > 1) {
      alert('addKey', 'danger', 'You must import a single file!');
      return;
    }
    const file = files[0];
    const reader = new FileReader();
    reader.onload = function(){
      $('#addKey textarea').val(reader.result);
    } 
    reader.readAsText(file);
   }

}(jQuery));
