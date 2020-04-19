(function($){
  $(function(){
    // Activate Materializa components
    $('.sidenav').sidenav();
    $('.tabs').tabs();
    $('.datepicker').datepicker({
      format: "dd/mm/yyyy",
      autoClose: true,
      firstDay: 1,
      defaultDate: Date.now()
    });
    $('select').formSelect();
    $('.modal').modal({
      onCloseEnd: function (){ $('#issue-btn').prop("disabled", false)},
      dismissible: false
    });

    $('.tab-activate').on('click', function(event) {
      event.preventDefault();
      let tab = $(this).attr('href').replace('#', '');
      $('.tabs').tabs('select', tab);
    });

    setToday($('#dateIssued'));
  });
})(jQuery);

// Set value to today
function setToday($selector) {
  var now = new Date();
  var month = (now.getMonth() + 1);
  var day = now.getDate();
  if (month < 10)
      month = "0" + month;
  if (day < 10)
      day = "0" + day;
  var today = day + '/' + month + '/' + now.getFullYear();
  $selector.val(today);
}
