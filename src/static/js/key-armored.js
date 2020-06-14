/* eslint-disable */

;(function($) {
  'use strict';
  
  $('#copy-button').tooltip({
    trigger: 'manual',
    placement: 'right',
  });

  function setTooltip(message) {
    $('#copy-button').attr('data-original-title', message)
      .tooltip('show');
  }

  function hideTooltip() {
    setTimeout(function() {
      $('#copy-button').tooltip('hide');
    }, 1000);
  }

  $('#copy-button').click(function(e) {
    const copyText = $('#publickey-block').text();
    const textArea = document.createElement('textarea');
    textArea.textContent = copyText;
    document.body.append(textArea);
    textArea.select();
    document.execCommand("copy");
    textArea.remove();
    
    setTooltip('Key copied to clipboard!');
    hideTooltip();
  });

}(jQuery));
