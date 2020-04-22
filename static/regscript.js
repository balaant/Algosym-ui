const staticInputData ={
    login: $("#login").val(),
    password: $("#password").val(),
    copypassword: $("#copypassword").val(),
    eyeflag: false,
    eyeflagcopy: false
};

$("#btn-notshow").hide();
$("#btn-notshow-copy").hide();
$(".btn-eye").click(function(){
   if(staticInputData.eyeflag == false){
       $("#btn-show").hide();
       $("#btn-notshow").fadeIn(500);
       $("#password").attr("type","text");
       staticInputData.eyeflag = true;
   } else {
       $("#btn-show").fadeIn(500);
       $("#btn-notshow").hide();
       $("#password").attr("type","password");
       staticInputData.eyeflag = false;
   }
});

$(".btn-eye-copy").click(function(){
    if(staticInputData.eyeflagcopy == false){
        $("#btn-show-copy").hide();
        $("#btn-notshow-copy").fadeIn(500);
        $("#copypassword").attr("type","text");
        staticInputData.eyeflagcopy = true;
    } else {
        $("#btn-show-copy").fadeIn(500);
        $("#btn-notshow-copy").hide();
        $("#copypassword").attr("type","password");
        staticInputData.eyeflagcopy = false;
    }
 });

function checkInput(x,y,z){
    if ( !(x == staticInputData.login) ) {
       $("#E-mail_hint").css("color","#737382");
       $("#login").attr("placeholder", "");
    } else{
       $("#E-mail_hint").css("color","#44434F"); 
       $("#login").attr("placeholder", "Ваш логин/e-mail");
    }
    if ( !(y == staticInputData.password) ) {
       $("#Password_hint").css("color","#737382");
       $("#password").attr("placeholder", "");
   } else{
       $("#Password_hint").css("color","#44434F");
       $("#password").attr("placeholder", "Пароль");
   }
   if ( !(z == staticInputData.copypassword) ) {
    $("#Copypassword_hint").css("color","#737382");
    $("#copypassword").attr("placeholder", "");
} else{
    $("#Copypassword_hint").css("color","#44434F");
    $("#copypassword").attr("placeholder", "Повторите пароль");
}

};
setInterval(function(){
   logVar = $("#login").val();
   passVar = $("#password").val();
   copypassVar = $("#copypassword").val();
   checkInput(logVar,passVar,copypassVar);
},100);

$("#btn-singup").click(function(){
    if( $("#password").val() !== $("#copypassword").val() || ($("#password").val() == staticInputData.password && $("#copypassword").val() ==staticInputData.copypassword) ){
        $("#copypassword").fadeOut(250);
        $("#password").fadeOut(250);
        $("#copypassword").fadeIn(250);
        $("#password").fadeIn(250);
    }
    if( $("#login").val() == staticInputData.login){
        $("#login").fadeOut(250);
        $("#login").fadeIn(250); 
    }
    
});