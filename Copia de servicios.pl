use IO::Socket;
$servidor="66.118.185.108";
$puerto=4400;
$pass="pitchblack";
$canaldebug="#opers";
$msgkill="Publicidad no Permitida en DarkBolt";
$nombre="pitch.black";
$numerico="90";
$descripcion="Servicios extras de la Red";
$password="pitchblack";
$bot="SuX";
$bot2="VHoST";
$bot3="CaLC";
$bot4="NiCK2";
#$bot5="SHaDoW";
##$bot6="AntiSpam";
#$bot7="NoExPiRe";
#$bot8="HeLP";
#$bot9="DeBuG";
#$bot10="CSoP";
$maxv="30";
$maxn="12";
$operschan="#opers";
$red="\$Devel.darkbolt.net";
$ident="-";
$host="-";
$namevhost="Servicio de Virtual Host";
$namesux="Servicio de I-Lines";
$namecalc="Servicio de Calculadora";
$namenick2="Servicio de Proteccion de Nicks";
$nameshadow="Guardian de los Modos de Canales";
$nameantispam="Servicio Anti-Publicitario";
$namehelp="Servicio de Ayuda al Usuario";
$namenoexpire="Servicio de No Expire de Nicks";
$namedebug="Servicio de Debug";
$namecsop="Servicio de Debug";
$nombrered="DarkBolt.org";
sub raw { print $socket join('', @_[0..$#_])."\r\n"; }
require 'vhost.help';
require 'creditos.help';
require 'calc.help';
require 'sux.help';
require 'nick2.help';
require 'shadow.help';
require 'vhostoper.help';
require 'calcoper.help';
require 'nick2oper.help';
require 'noexpire.help';
require 'noexpireoper.help';
require 'help.help';
require 'helpoper.help';
#require 'debug.help';
#require 'csop.help';
#require 'csopoper.help';
         
#if (fork()) { exit(-1); }

$socket = IO::Socket::INET->new(	
 		Proto => "tcp",
 		PeerAddr => $servidor,
 		PeerPort => $puerto,
) or die "No se ha podido conectar con el servidor\n";

print $socket "PASS :$password\r\n";
print $socket "SERVER $nombre 1 ",time," ",time," P10 ${numerico}P] :$descripcion\r\n";
print $socket "$numerico N $bot 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AA :$namesux\r\n";
print $socket "$numerico N $bot2 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AB :$namevhost\r\n";
print $socket "$numerico N $bot3 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AC :$namecalc\r\n";
print $socket "$numerico N $bot4 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AD :$namenick2\r\n";
print $socket "$numerico N $bot5 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AE :$nameshadow\r\n";
#print $socket "$numerico N $bot6 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AF :$nameantispam\r\n";
print $socket "$numerico N $bot8 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AG :$namehelp\r\n";
print $socket "$numerico N $bot7 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AH :$namenoexpire\r\n";
#print $socket "$numerico N $bot9 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AI :$namedebug\r\n";
#print $socket "$numerico N $bot10 1 ",time," $ident $host +okidBrhX DDNSca ${numerico}AJ :$namecsop\r\n";
print $socket "${numerico}AA J $operschan\r\n";
print $socket "${numerico}AA M $operschan +o ${numerico}AA\r\n"; 
print $socket "${numerico}AB J $operschan\r\n";
print $socket "${numerico}AB M $operschan +o ${numerico}AB\r\n"; 
print $socket "${numerico}AC J $operschan\r\n";
print $socket "${numerico}AC M $operschan +o ${numerico}AC\r\n"; 
print $socket "${numerico}AD J $operschan\r\n";
print $socket "${numerico}AD M $operschan +o ${numerico}AD\r\n"; 
print $socket "${numerico}AE J $operschan\r\n";
print $socket "${numerico}AE M $operschan +o ${numerico}AE\r\n"; 
print $socket "${numerico}AF J $operschan\r\n";
print $socket "${numerico}AF M $operschan +o ${numerico}AF\r\n"; 
print $socket "${numerico}AG J $operschan\r\n";
print $socket "${numerico}AG M $operschan +o ${numerico}AG\r\n"; 
print $socket "${numerico}AH J $operschan\r\n";
print $socket "${numerico}AH M $operschan +o ${numerico}AH\r\n"; 
print $socket "${numerico}AI J $operschan\r\n";
print $socket "${numerico}AI M $operschan +o ${numerico}AI\r\n"; 
print $socket "${numerico}AI J $canaldebug\r\n";
print $socket "${numerico}AI M $canaldebug +o ${numerico}AI\r\n"; 
print $socket "${numerico}AJ J $operschan\r\n";
print $socket "${numerico}AJ M $operschan +o ${numerico}AJ\r\n"; 
print $socket "$nombre P $operschan : 4Services1 Conectados con Exito.\n";
while (<$socket>) {
 	@datos=split(/ /, $_);
	chop($datos[$#datos]);
 	chop($datos[$#datos]);
 	if (($datos[1] eq "PING") or ($datos[1] eq "G")) {
 		print $socket "$numerico PONG $datos[2]\r\n";
		next;
 	}
	if ($datos[1] eq "DB") {
	if ($datos[4] eq "J") {
		if ($datos[6] == 2) { $serie{'n'}=$datos[5]; print $socket "$numerico DB * 0 J $datos[5] 2\r\n"; }
		else { $serie{$datos[6]}=$datos[5]; }
		}
	}
	if ($datos[1] eq "NICK") {
	if (length($datos[0])==1) {
		if ($datos[7] =~ /^\+/) {
			$NickNumeric{lc($datos[2])} = $datos[9];
			$NumericNick{$datos[9]} = $datos[2];
		}
		else {
			$NickNumeric{lc($datos[2])} = $datos[8];
			$NumericNick{$datos[8]} = $datos[2];
		}
	}
	else {
		undef $NickNumeric{lc($NumericNick{$datos[0]})};
		$NumericNick{$datos[0]} = $datos[2];
		$NickNumeric{lc($datos[2])} = $datos[0];
		}
	}
	if ($datos[1] eq "PRIVMSG") {
 	$datos[3] =~ s/://;
	$datos[0] =~ s/://;
	$trio=$NickNumeric{lc($datos[0])};
################## PRINCIPIO DE SuX ####################
        if ($datos[2] =~/${numerico}AA/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
         print $socket "${numerico}AA DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AA P $bot :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
          print $socket "${numerico}AA P $trio :4Acceso Denegado!\n";
         }
         else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
		foreach (@suxhelp) { print $socket "${numerico}AA P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AA P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
       ####### ADDILINE #####
		if (@datos[3] =~/addiline/i) {
			if ($datos[4] eq "" or $datos[5] eq "") {
        		&raw("${numerico}AA P $trio :Comando Incorrecto.12 /msg $bot ADDILINE <Host> <Clones>");
        		next;
        		}
                  else {
                  print $socket "${numerico}AA DBQ * i $datos[4]\n";
                  defined ($text = <$socket>);
                  print $socket "${numerico}AA P $bot :$text\n";
                  if ($text =~ REGISTRO_NO_ENCONTRADO) {
			$serie{'i'}++;
                        print $socket "$numerico DB * $serie{'i'} i $datos[4] $datos[5]\n";
                        print $socket "${numerico}AA P $trio :A�adida I-Line, de Host:12 $datos[4] 1con Clones:12 $datos[5]\n";
                        print $socket "${numerico}AA P $operschan :$datos[0] Ha A�adido I-Line, de Host:12 $datos[4] 1con Clones:12 $datos[5]\n";
			}
                  else {
                   print $socket "${numerico}AA P $trio :La Host ya esta registrada en 12SuX\n";
                  }
             }
	     }	
       ###### DELILINE #####
			if (@datos[3] =~/deliline/i) {
			if ($datos[4] eq "") {
			&raw("${numerico}AA P $trio :Comando Incorrecto.12 /msg $bot DELILINE <Host>");
			next;
			}
                  else {
                  print $socket "${numerico}AA DBQ * i $datos[4]\n";
                  defined ($text = <$socket>);
                  print $socket "${numerico}AA P $bot :$text\n";
                  if ($text =~ REGISTRO_NO_ENCONTRADO) {
                    print $socket "${numerico}AA P $trio :No se puede borrar una iline a una host que no existe en la 12BDD\n";
                  }
                  else {
			$serie{'i'}++;
			print $socket "$numerico DB * $serie{'i'} i $datos[4]\r\n";
			&raw("${numerico}AA P $trio :Borrada I-Line de Host:12 $datos[4]");
			&raw("${numerico}AA P $operschan :$datos[0] Ha Borrado I-Line de Host:12 $datos[4]");
			}
               }
             }
######### INFO #############
if ($datos[3] =~/info/i) {
 if ($datos[4] eq "") {
  print $socket "${numerico}AA P $trio :Comando Incorrecto.12/msg $bot INFO <Host>\n";
 }
  else {
print $socket "${numerico}AA DBQ * i $datos[4]\n";
  defined ($text = <$socket>);
  print $socket "${numerico}AA P $bot :$text\n";
  if ($text =~ REGISTRO_NO_ENCONTRADO) {
   print $socket "${numerico}AA P $trio :La Host12 $datos[4] 1no esta registrada.\n";
  }
  else {
   print $socket "${numerico}AA P $trio :La Host12 $datos[4] 1esta registrada.\n";
  }
}
}
###### NUMERO DE CLONES A ADMITIR #####
			if (@datos[3] =~/clones/i) {
			if ($datos[4] eq "") {
			&raw("${numerico}AA P $trio :Comando Incorrecto.12 /msg $bot CLONES <Numero_de_Clones>");
			next;
			}
			$serie{'i'}++;
			print $socket "$numerico DB * $serie{'i'} i . $datos[4]\r\n";
			&raw("${numerico}AA P $trio :Has Cambiado el Maximo de Clones por:12 $datos[4]");
			&raw("${numerico}AA P $operschan :$datos[0] Ha Cambiado el Maximo de Clones por:12 $datos[4]");
			}
######### JOIN ######

		if ($datos[3] =~/join/i) {
		if ($datos[4] eq "") {
                &raw("${numerico}AA P $trio :Comando Incorrecto.12 /msg $bot JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AA J $datos[4]\r\n";
            &raw("${numerico}AA P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AA P $operschan :$datos[0] Ha Metido a12 $bot 1en12 $datos[4]");
		}
######### PART #######
		if (@datos[3] =~/part/i) {
                if ($datos[4] eq "") {
                &raw("${numerico}AA P $trio :Comando Incorrecto.12 /msg $bot PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AA P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AA L $datos[4]\r\n";
            &raw("${numerico}AA P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AA P $operschan :$datos[0] Ha Sacado a12 $bot 1de12 $datos[4]");
                }
          
      }
	        }
}
 ######################## FIN DE SUX Y PRINCIPIO DE VHoST #############
        if ($datos[2] =~/${numerico}AB/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
         print $socket "${numerico}AB DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AB P $bot2 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
		foreach (@vhosthelp) { print $socket "${numerico}AB P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }         
         else {
		foreach (@vhostoperhelp) { print $socket "${numerico}AB P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
        }
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AB P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}

######### INFO #############
if ($datos[3] =~/info/i) {
 if ($datos[4] eq "") {
  &raw("${numerico}AB P $trio :Comando Incorrecto.12 /msg $bot2 INFO <Nick>");
 }
  else {
print $socket "${numerico}AB DBQ * v $datos[4]\n";
  defined ($text = <$socket>);
  print $socket "${numerico}AB P $bot2 :$text\n";
  if ($text =~ REGISTRO_NO_ENCONTRADO) {
   print $socket "${numerico}AB P $trio :La Vhost de12 $datos[4] 1no esta registrada.\n";
  }
  else {
   print $socket "${numerico}AB P $trio :La Vhost de12 $datos[4] 1esta registrada.\n";
  }
}
}
##################################################
## VHoST
if ($datos[3] =~/vhost/i) {
if ($datos[4] eq "") {
print $socket "${numerico}AB P $trio  :Comando Incorrecto.12 /msg $bot2 VHOST <la-vHost>\n"; }
elsif ($datos[4] =~/oper/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/pre-oper/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/devel/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/0per/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/bot/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/admin/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/ircop/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/lrcop/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/server/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/www/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/http/i) { print $socket "${numerico}AB P $trio  :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/puta/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/gay/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/gei/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/jilipoya/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/poya/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
elsif ($datos[4] =~/co�o/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }                                                      
elsif ($datos[4] =~/zorra/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }  
elsif ($datos[4] =~/help/i) { print $socket "${numerico}AB P $trio :Esa VHoST no puedes ponertela,lo siento.\n"; }
else {
print $socket "${numerico}AB DBQ n $datos[0]\n";
defined ($texto = <$socket>);
if ($texto =~ REGISTRO_NO_ENCONTRADO) { print $socket "${numerico}AD P $trio :No estas registrado en NiCK2,para poder ponerte VHOST registrate en NiCK2.\n"; }
else {
$serie{'v'}++;
print $socket "$numerico DB * $serie{'v'} v $datos[0] $datos[4].spainchat.vip\n";
print $socket "${numerico}AB P $trio  :Tu VHoST ha sido cambiada a:12 $datos[4].spainchat.vip\n";
print $socket "${numerico}AB P $trio  :Para que funcione cambiese el nick y pongaselo de nuevo.\n";
} 
}
}
###### DELVHOST #####
if ($datos[3] =~/delhost/i) {
 print $socket "${numerico}AB DBQ n $datos[0]\n";
  defined ($text = <$socket>);
  print $socket "${numerico}AB P $bot2 :$text\n";
  if ($text =~ REGISTRO_NO_ENCONTRADO) {
   print $socket "${numerico}AB P $trio :El Nick12 $datos[0] 1no esta registrado.\n";
} 
 else {
 $serie{'v'}++;
 print $socket "$numerico DB * $serie{'v'} v $datos[0]\n";
 print $socket "${numerico}AB P $trio :Borrada tu VHoST 12 $datos[0]\n";
 print $socket "${numerico}AB P $operschan :$datos[0] se ha borrado su VHoST\n";
}
}

######### JOIN ######
		if ($datos[3] =~/join/i) {
         print $socket "${numerico}AB DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AB P $bot2 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AB P $trio :Comando Incorrecto.12 /msg $bot2 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AB J $datos[4]\r\n";
            &raw("${numerico}AB P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AB P $operschan :$datos[0] Ha Metido a12 $bot2 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AB DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AB P $bot2 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AB P $trio :Comando Incorrecto.12 /msg $bot2 PART <#Canal>");
                next;                 }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AB P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AD L $datos[4]\r\n";
            &raw("${numerico}AB P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AB P $operschan :$datos[0] Ha Sacado a12 $bot2 1de12 $datos[4]");
                }
		}
		}
            }    

#################### TERMINACION DE VHOST Y EMPIEZE DE CALC ##############
        if ($datos[2] =~/${numerico}AC/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
              print $socket "${numerico}AC DBQ * o $datos[0]\n";
              defined ($text = <$socket>);
              print $socket "${numerico}AC P $bot3 :$text\n";
              if ($text =~ REGISTRO_NO_ENCONTRADO) {
               foreach (@calchelp) { print $socket "${numerico}AC P $NickNumeric{lc($datos[0])} :$_\r\n"; }
              }
              else {
      		foreach (@calcoperhelp) { print $socket "${numerico}AC P $NickNumeric{lc($datos[0])} :$_\r\n"; }
           }
         }
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
    		foreach (@creditos) { print $socket "${numerico}AC P $NickNumeric{lc($datos[0])} :$_\r\n"; }             }
############### SUMA #############
if ($datos[3] =~/suma/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 SUMA <numero1> <numero2>");
  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $suma = $datos[4] + $datos[5];
  print $socket "${numerico}AC PRIVMSG $trio : La suma de2 $datos[4] 1m�s12 $datos[5] 1es igual a12 $suma\n";
 }
 if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
}
}
############### RESTA #############
if ($datos[3] =~/resta/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 RESTA <numero1> <numero2>");
  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $resta = $datos[4] - $datos[5];
  print $socket "${numerico}AC PRIVMSG $trio : La resta de12 $datos[4] 1menos12 $datos[5] 1es igual a12 $resta\n";
 }
 if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
 }
}

############### MULTIPLICACION #############
if ($datos[3] =~/multiplicacion/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 MULTIPLICACION <numero1> <numero2>");
  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $multiplicacion = $datos[4] * $datos[5];
  print $socket "${numerico}AC PRIVMSG $trio : La multiplicacion de12 $datos[4] 1por12 $datos[5] 1es igual a12 $multiplicacion\n";
 }
 if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
 }
}

############### DIVISION #############
if ($datos[3] =~/division/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
    &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 DIVISION <numero1> <numero2>");

  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $division = $datos[4] / $datos[5];
  print $socket "${numerico}AC PRIVMSG $trio : La division de12 $datos[4] 1entre12 $datos[5] 1es igual a12 $division\n";
 }
 if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
 }
}

############### EURPTS #############
if ($datos[3] =~/eurpts/i) {
 if ($datos[4] eq "") {
  &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 EURPTS <numero>");
  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $eurpts = $datos[4]*1000/6;
  print $socket "${numerico}AC PRIVMSG $trio : 12 $datos[4] Euros 1pasados a 12Pesetas1 son12 $eurpts pts\n";
 }
 if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
 }
}

############### PTSEUR #############
if ($datos[3] =~/ptseur/i) {
 if ($datos[4] eq "") {
  &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 PTSEUR <numero>");
  }
 if ($datos[4] =~ /[0-9]/ or $datos[5] =~ /[0-9]/) {
  $ptseur = $datos[4]*6/1000;
  print $socket "${numerico}AC PRIVMSG $trio : 12 $datos[4] pts 1pasados a 12Euros1 son12 $ptseur euros\n";
  }
  if ($datos[4] =~ /[a-z]/ or $datos[5] =~ /[a-z]/) {
 print $socket "${numerico}AC PRIVMSG $trio : Utiliza Numeros no Letras.\n";
 }
}
######### JOIN ######
		if (@datos[3] =~/join/i) {
         print $socket "${numerico}AC DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AC P $bot3 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AC J $datos[4]\r\n";
            &raw("${numerico}AC P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AC P $operschan :$datos[0] Ha Metido a12 $bot3 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AC DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AC P $bot3 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AC P $trio :Comando Incorrecto.12 /msg $bot3 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AC P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AC L $datos[4]\r\n";
            &raw("${numerico}AC P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AC P $operschan :$datos[0] Ha Sacado a12 $bot3 1de12 $datos[4]");
                }
		}
		}
            }
################## FINAL DE CALC Y EMPIEZE DE NICK2 #############
        if ($datos[2] =~/${numerico}AD/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
         print $socket "${numerico}AD DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AD P $bot4 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
		foreach (@nick2help) { print $socket "${numerico}AD P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }         
         else {
		foreach (@nick2operhelp) { print $socket "${numerico}AD P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
        }
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AD P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}

                                                    ##################################################
                                                    ## DROP
                                                    if ($datos[3] =~/drop/i) {

                                                       $serie{'n'}++;
                                                       $serie{'v'}++;
                                                    	print $socket "$numerico DB * $serie{'n'} n $datos[0]\n";
                                                    	print $socket "$numerico DB * $serie{'v'} v $datos[0]\n";
                                                      
                                                      print $socket "${numerico}AD P $trio :A sido borrado el modo +r y vhost de su nick.\n";
                                                      print $socket "${numerico}AD P $trio :Para que el cambio tenga efecto cambiese el nick.\n";

                                                    }

                                                      ##################################################
                                                      ## REGISTER
                                                      if ($datos[3] =~/register/i) {
$elnick="$datos[0]";
$datos[0] =~ s/\^/\~/g;
$datos[0] =~ s/\[/\{/g;
$datos[0] =~ s/\]/\}/g;
$datos[0]=~y/[A-Z]/[a-z]/;
                                                        if ($datos[4] eq "") {
                                                          print $socket "${numerico}AD P $trio :Sintaxis:12 /msg $bot4 REGISTER <contrase�a>\n";
                                                          				}
elsif (length($datos[4]) > 30) { print $socket "${numerico}AD P $trio :La contrase�a supera el numero maximo de caracteres.\n"; }
elsif (length($datos[4]) < 5) { print $socket "${numerico}AD P $trio :Pruebe con una contrase�a mas larga.\n"; }
                                                            else {
print $socket "${numerico}AC P $trio{NiCK} :set $datos[0] password $datos[4]\n"; 
                                                              print $socket "${numerico}AD P $trio :Porfavor cambiese el nick y vuelva a ponerselo con el comando 12/nick $elnick:$datos[4]\n";
open(TEA, "./tea \"$datos[0]\" $datos[4]|");
                                                    @tea=split(/ /, <TEA>);

                                                    	$serie{'n'}++;
                                                    	print $socket "$numerico DB * $serie{'n'} n @tea\n";

                                                    close(TEA);
                                                            } 
                                                          }    

                                                      ##################################################
                                                      ## SETPASS
                                                      if ($datos[3] =~/setpass/i) {
$elnick="$datos[0]";
$datos[0] =~ s/\^/\~/g;
$datos[0] =~ s/\[/\{/g;
$datos[0] =~ s/\]/\}/g;
$datos[0]=~y/[A-Z]/[a-z]/;
                                                        if ($datos[4] eq "") {
                                                          print $socket "${numerico}AD P $trio :Sintaxis:12 /msg $bot4 SETPASS <contrase�a>\n";
                                                          				}
elsif (length($datos[4]) > 30) { print $socket "${numerico}AD P $trio :La contrase�a supera el numero maximo de caracteres.\n"; }
elsif (length($datos[4]) < 5) { print $socket "${numerico}AD P $trio :Pruebe con una contrase�a mas larga.\n"; }
                                                            else {
print $socket "${numerico}AC P $trio{NiCK} :set $datos[0] password $datos[4]\n"; 
                                                              print $socket "${numerico}AD P $trio :Contrase�a cambiada a: $datos[4]\n";
                                                              print $socket "${numerico}AD P $trio :Porfavor cambiese el nick y vuelva a ponerselo con el comando 12/nick $elnick:$datos[4]\n";
open(TEA, "./tea \"$datos[0]\" $datos[4]|");
                                                    @tea=split(/ /, <TEA>);

                                                    	$serie{'n'}++;
                                                    	print $socket "$numerico DB * $serie{'n'} n @tea\n";

                                                    close(TEA);
                                                            } 
                                                          }           
                                                        



######### INFO #############
if ($datos[3] =~/info/i) {
 if ($datos[4] eq "") {
  print $socket "${numerico}AD P $trio :Comando Incorrecto.12/msg $bot4 INFO <Nick>\n";
 }
  else {
  print $socket "${numerico}AD DBQ n $datos[4]\n";
  defined ($text = <$socket>);
  print $socket "${numerico}AD P $operschan :$text\n";
  if ($text =~ REGISTRO_NO_ENCONTRADO) {
   print $socket "${numerico}AD P $trio :El Nick12 $datos[4] 1no esta registrado.\n";
  }
  else {
   print $socket "${numerico}AD P $trio :El Nick12 $datos[4] 1esta registrado.\n";
  }
}
}

######### JOIN ######
		if ($datos[3] =~/join/i) {
         print $socket "${numerico}AD DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AD P $bot4 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AD P $trio :Comando Incorrecto.12 /msg $bot4 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AD J $datos[4]\r\n";
            &raw("${numerico}AD P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AD P $operschan :$datos[0] Ha Metido a12 $bot4 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AD DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AD P $bot4 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AD P $trio :Comando Incorrecto.12 /msg $bot4 PART <#Canal>");
                next;                 }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AD P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AD L $datos[4]\r\n";
            &raw("${numerico}AD P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AD P $operschan :$datos[0] Ha Sacado a12 $bot4 1de12 $datos[4]");
                }
		}
		}
            }
############# FINAL DE NICK2 Y EMPIEZE DE SHADOW #############
        if ($datos[2] =~/${numerico}AE/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
         print $socket "${numerico}AE DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AE P $bot5 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
		foreach (@shadowhelp) { print $socket "${numerico}AE P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AE P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
####### ENTRADA POR CAMBIO DE MODOS ###########
if ($datos[0] eq "OPeR") {
 if (@datos[3] =~/JOIN/i) {
  print $socket "${numerico}AE J $datos[4]\r\n";
 }
 if (@datos[3] =~/PART/i) {
  print $socket "${numerico}AE PART $datos[4]\r\n";
 }
}

######### JOIN ######
		if ($datos[3] =~/join/i) {
		if ($datos[4] eq "") {
                &raw("${numerico}AE P $trio :Comando Incorrecto.12 /msg $bot5 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AE J $datos[4]\r\n";
		}
######### PART #######
		if (@datos[3] =~/part/i) {
                if ($datos[4] eq "") {
                &raw("${numerico}AE P $trio :Comando Incorrecto.12 /msg $bot5 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AE P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
            print $socket "${numerico}AE PART $datos[4]\r\n";
   }
}
}
}
############ FINAL DE SHADOW EMPIEZE DE ANTISPAM ############
#        if ($datos[2] =~/${numerico}AF/i) {
#           if ($datos[2] =~/#/i) { 
#           print $socket "NADA o : $_\n"; 
#        }
#       else {
########### FINAL DE ANTISPAM Y EMPIEZE DE NOEXPIRE ###########
        if ($datos[2] =~/${numerico}AH/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
         print $socket "${numerico}AH DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AH P $bot7 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
          foreach (@noexpirehelp) { print $socket "${numerico}AH P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
         else {
		foreach (@noexpireoperhelp) { print $socket "${numerico}AH P $NickNumeric{lc($datos[0])} :$_\r\n"; }
	   }
         }
######### CREDITOS #####
          if (@datos[3] =~/creditos/i) {
             foreach (@creditos) { print $socket "${numerico}AH P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
######### JOIN ######
		if (@datos[3] =~/join/i) {
         print $socket "${numerico}AH DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AH P $bot7 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AH P $trio :Comando Incorrecto.12 /msg $bot7 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AH J $datos[4]\r\n";
            &raw("${numerico}AH P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AH P $operschan :$datos[0] Ha Metido a12 $bot7 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AH DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AH P $bot7 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AH P $trio :Comando Incorrecto.12 /msg $bot7 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AH P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AH L $datos[4]\r\n";
            &raw("${numerico}AH P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AH P $operschan :$datos[0] Ha Sacado a12 $bot7 1de12 $datos[4]");
                }
		}
##### ALTA #####
    if (@datos[3] =~/ALTA/i) {
              print $socket "{numerico}AH P $trio :Tu nick ha sido dado de alta en 12NoExPiRe\n";
              print $socket "{numerico}AH P $trio{NiCK} :set $datos[0] noexpire on\n";
         }
##### BAJA #####
    if (@datos[3] =~/BAJA/i) {
              print $socket "{numerico}AH P $trio :Tu nick ha sido dado de baja en 12NoExPiRe\n";
              print $socket "{numerico}AH P $trio{NiCK} :set $datos[0] noexpire off\n";
           }
 
            }
            }
################## PRINCIPIO DE HeLP ####################
        if ($datos[2] =~/${numerico}AG/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
         print $socket "${numerico}AG DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AG P $bot15 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
          foreach (@helphelp) { print $socket "${numerico}AG P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
         else {
		foreach (@helpoperhelp) { print $socket "${numerico}AG P $NickNumeric{lc($datos[0])} :$_\r\n"; }
	   }
         }
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AG P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
################### COMANDOS ##############
if (@datos[3] =~/IRCOPS/i) {
 print $socket "${numerico}AG P $trio : Para mostrar la lista de todos los ircops activos en la red\n";
 print $socket "${numerico}AG P $trio : de SpainChat solo tienes que poner el siguiente comando\n";
 print $socket "${numerico}AG P $trio : Sintaxis:12/msg CHaN IRCOPS\n";
}
if (@datos[3] =~/FLAG/i) {
 print $socket "${numerico}AG P $trio : Para que tu nick este seguro y nadie se lo pueda poner ni\n";
 print $socket "${numerico}AG P $trio : 20 segundos aqui tenemos nuestro nuevo servicio para su utilizacion\n";
 print $socket "${numerico}AG P $trio : solo requiere tener el nick registrado en el bot NiCK una vez eso\n";
 print $socket "${numerico}AG P $trio : abres un privado a NiCK2 y le escribes el siguente comando:\n";
 print $socket "${numerico}AG P $trio : Sintaxis:12 /msg NiCK2 REGISTER <clave>\n";
}
if (@datos[3] =~/NICK/i) {
 print $socket "${numerico}AG P $trio : Para registrar un nick debes conocer mas o menos los comandos\n";
 print $socket "${numerico}AG P $trio : del bot NiCK, para hallar todos sus comandos ponga /msg NiCK HELP\n";
 print $socket "${numerico}AG P $trio : Si lo que quieres es solo registrar el NiCK en la Base de Datos del\n";
 print $socket "${numerico}AG P $trio : bots escriba el siguiente comando:\n";
 print $socket "${numerico}AG P $trio : Sintaxis:12 /msg NiCK REGISTER <e@mail.com>\n";
}
if (@datos[3] =~/CANAL/i) {
 print $socket "${numerico}AG P $trio : Para registrar un canal debes utilizar el bot CReG ya que el bot CHaN\n";
 print $socket "${numerico}AG P $trio : su uso no es ese,para listar los comandos ponga /msg CReG HELP\n";
 print $socket "${numerico}AG P $trio : luego utilize el comando:12/msg CReG REGISTRA <#canal> <contrase�a> <descripcion>\n";
 print $socket "${numerico}AG P $trio : luego necesitaras 5 apoyos es decir que 5 usuarios apoyen al canal el comando es:\n";
 print $socket "${numerico}AG P $trio : Sintaxis:12 /msg CReG APOYA <#Canal>\n";
}

if (@datos[3] =~/VHoST/i) {
 print $socket "${numerico}AG P $trio : Para obtener tu propia vhost necesitaras tener el nick registrado y con\n";
 print $socket "${numerico}AG P $trio : el flag +r del bot NiCK2,Si tienes todo eso despues necesitaras por\n";
 print $socket "${numerico}AG P $trio : el siguiente comando:12/msg VHOST <la-vhost>\n";
 print $socket "${numerico}AG P $trio : Ten encuenta que el bot prohibe algunas vhost como palabras malsonantes o \n";
 print $socket "${numerico}AG P $trio : palabras inapropiadas como Admin,Oper,Pre-oper,ect...\n";
}
if (@datos[3] =~/UMODES/i) {
 print $socket "${numerico}AG P $trio : Los modos posibles en la red de IRC-Eclipse son los siguientes:\n";
 print $socket "${numerico}AG P $trio : \n";
 print $socket "${numerico}AG P $trio : 12r1 Nick registrado y protegido\n";
 print $socket "${numerico}AG P $trio : 12x1 Proteccion de IP contra nukes (ip virtual)\n";
 print $socket "${numerico}AG P $trio : 12i1 Modo invisible (No aparece utilizando /who)\n";
 print $socket "${numerico}AG P $trio : 12s1 Recibir noticias del servidor\n";
 print $socket "${numerico}AG P $trio : 12w1 Recibir wallops\n";
 print $socket "${numerico}AG P $trio : 12g1 Recibir mensajes del servidor si esta en modo DEBUG\n";
 print $socket "${numerico}AG P $trio : \n";
 print $socket "${numerico}AG P $trio : Modos de IRCop/Operador/Admin:\n";
 print $socket "${numerico}AG P $trio : \n";
 print $socket "${numerico}AG P $trio : 12h1 OPERador de MundoLatin\n";
 print $socket "${numerico}AG P $trio : 12o1 Ircop de MundoLatin\n";
 print $socket "${numerico}AG P $trio : 12X1 Ver las ips REALES a usuarios que tienen +x\n";
 print $socket "${numerico}AG P $trio : 12X1 ADMINistrador de MundoLatin\n";
 print $socket "${numerico}AG P $trio : \n";
 print $socket "${numerico}AG P $trio : Para cambiar los modos de usuario, escriba 12/mode nick {+/-}modos.\n";
 print $socket "${numerico}AG P $trio : La12 + 1es para agregar modos y la12 - 1para quitar modos.\n";
 print $socket "${numerico}AG P $trio : El modo12 r 1de nick registrado no se puede poner ni quitar a voluntad.\n";
}
if (@datos[3] =~/SERVERS/i) {
  print $socket "${numerico}AG P $trio : Para ver la lista de servers linkados basta ponga en la barra de status /links\n";
}

if (@datos[3] =~/BOTS/i) {
 print $socket "${numerico}AG P $trio : Lista de los Bots Linkeados a MundoLatin:\n";
 print $socket "${numerico}AG P $trio : \n";
 print $socket "${numerico}AG P $trio : 4CHaN Servicio de mantenimiento de canales.\n";
 print $socket "${numerico}AG P $trio : 4CReG Servicio de registro de canales.\n";
 print $socket "${numerico}AG P $trio : 4NiCK Servicio de registro y mantenimento de Nicks.\n";
 print $socket "${numerico}AG P $trio : 4MeMO Servicio de mensajer�a entre usuarios.\n";
 print $socket "${numerico}AG P $trio : 4SHaDoW Servicio de guard�an de modos.\n";
 print $socket "${numerico}AG P $trio : 4OPeR Servicio s�lo para OPERS/IRCOPS.\n";
 print $socket "${numerico}AG P $trio : 4CoNTRoL Servicio de control de la Red.\n";
 print $socket "${numerico}AG P $trio : 4GLoBaL Servicio de mensajer�a global.\n";
 print $socket "${numerico}AG P $trio : 4NeWs Servicio de noticias de la red.\n";
 print $socket "${numerico}AG P $trio : 4NiCK2 Servicio de proteccion de Nicks.\n";
 print $socket "${numerico}AG P $trio : 4SuX Servicio de Control de Clones.\n";
 print $socket "${numerico}AG P $trio : 4VHoST Servicio de IPs Virtuales.\n";
 print $socket "${numerico}AG P $trio : 4CaLC Servicio de Calculos del IRC.\n";
 print $socket "${numerico}AG P $trio : 4NoExPiRe Servicio de No Expire del Nick.\n";
 print $socket "${numerico}AG P $trio : 4ZeuS Servicio de apoyo a los Operadores.\n";
 print $socket "${numerico}AG P $trio : 4AntiSpam Servicio control de SPAM\n";


}
######### JOIN ######
		if (@datos[3] =~/join/i) {
         print $socket "${numerico}AG DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AG P $bot20 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AG P $trio :Comando Incorrecto.12 /msg $bot20 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AG J $datos[4]\r\n";
            &raw("${numerico}AG P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AG P $operschan :$datos[0] Ha Metido a12 $bot20 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AG DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AG P $bot20 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AG P $trio :Comando Incorrecto.12 /msg $bot20 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AG P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AG L $datos[4]\r\n";
            &raw("${numerico}AG P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AG P $operschan :$datos[0] Ha Sacado a12 $bot3 1de12 $datos[4]");
                }
          }
 }
 }
############ FINAL DEL HELP Y EMPIEZE DE DEBUG #############
        if ($datos[2] =~/${numerico}AI/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
         print $socket "${numerico}AI DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AI P $bot9 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
          foreach (@helphelp) { print $socket "${numerico}AI P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
         else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
		foreach (@debughelp) { print $socket "${numerico}AI P $NickNumeric{lc($datos[0])} :$_\r\n"; }
	   }
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AI P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
######### DEBUG ##############
          	if ($datos[1] eq "NICK") {
            print $socket "${numerico}AI P $canaldebug : $_\n";
          }
          	if ($datos[1] eq "QUIT") {
            print $socket "${numerico}AI P $canaldebug : $_\n";
          }
          	if ($datos[1] eq "KILL") {
            print $socket "${numerico}AI P $canaldebug : $_\n";
          }
          	if ($datos[1] eq "GLINE") {
            print $socket "${numerico}AI P $canaldebug : $_\n";
          }
######### JOIN ######
		if (@datos[3] =~/join/i) {
         print $socket "${numerico}AI DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AI P $bot9 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
		if ($datos[4] eq "") {
                &raw("${numerico}AI P $trio :Comando Incorrecto.12 /msg $bot9 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AI J $datos[4]\r\n";
            &raw("${numerico}AI P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AI P $operschan :$datos[0] Ha Metido a12 $bot9 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AI DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AI P $bot20 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
         }
         else {
                if ($datos[4] eq "") {
                &raw("${numerico}AI P $trio :Comando Incorrecto.12 /msg $bot9 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AI P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AI L $datos[4]\r\n";
            &raw("${numerico}AI P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AI P $operschan :$datos[0] Ha Sacado a12 $bot9 1de12 $datos[4]");
                }
          }
}
}
}
############ FINAL DEL DEBUG Y EMPIEZE DE CSOP #############
        if ($datos[2] =~/${numerico}AJ/i) {
           if ($datos[2] =~/#/i) { 
           print $socket "NADA o : $_\n"; 
        }
       else {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ REGISTRO_NO_ENCONTRADO) {
          print $socket "{numerico}AJ P $trio :Acceso Denegado!\n";
         }
         else {
 ######### HELP #####
		if (@datos[3] =~/help/i) {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ 7) {
           foreach (@csophelp) { print $socket "${numerico}AJ P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
         if ($text =~ 10) {
           foreach (@csopoperhelp) { print $socket "${numerico}AJ P $NickNumeric{lc($datos[0])} :$_\r\n"; }
         }
}
####### OP ########
if (@datos[3] =~/OP/i) {
    if ($datos[4] eq "" or $datos[5] eq "") {
     print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 OP <#Canal> <Nick>\n";
    }
    else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] +o $trio{$datos[5]}\n";
     print $socket "${numerico}AJ P $trio :Ha sido OPeado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### DEOP ########
if (@datos[3] =~/DEOP/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 DEOP <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] -o $trio{$datos[5]}\n";
     print $socket "${numerico}AJ P $trio :Ha sido DEOPeado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### VOICE ########
if (@datos[3] =~/VOICE/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 VOICE <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] +v $trio{$datos[5]}\n";
     print $socket "${numerico}AJ P $trio :Ha sido VOICEado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### DEVOICE ########
if (@datos[3] =~/DEVOICE/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 DEVOICE <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] -v $trio{$datos[5]}\n";
     print $socket "${numerico}AJ P $trio :Ha sido DEVOICEado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### KICK ########
if (@datos[3] =~/KICK/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 KiCK <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ KICK $datos[4] $trio{$datos[5]} Kick Ordenado por $datos[0]\n";
     print $socket "${numerico}AJ P $trio :Ha sido KICKeado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### BAN ########
if (@datos[3] =~/BAN/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 BAN <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] +b $trio{$datos[5]}!*@*\n";
     print $socket "${numerico}AJ P $trio :Ha sido BARNeado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### KICKBAN ########
if (@datos[3] =~/KICKBAN/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 KICKBAN <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] +b $trio{$datos[5]}!*@*\n";
     print $socket "${numerico}AJ KICK $datos[4] $trio{$datos[5]} Kick Ordenado por $datos[0]\n";
     print $socket "${numerico}AJ P $trio :Ha sido BARNeado y KICKeado el Nick:12 $datos[4] 1en12 $datos[5]\n";
    }
  } 
}
####### INVITE ########
if (@datos[3] =~/INVITE/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 INVITE <#Canal> <Nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ INVITE $datos[4] $trio{$datos[5]}\n";
     print $socket "${numerico}AJ P $trio :Ha sido invitado el Nick:12 $datos[5] 1en12 $datos[4]\n";
    }
  } 
}
####### MODE ########
if (@datos[3] =~/MODE/i) {
 if ($datos[4] eq "" or $datos[5] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 MODE <#Canal> <+modos>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ MODE $datos[4] $datos[5]\n";
     print $socket "${numerico}AJ P $trio :Ha sido cambiado los modos:12 $datos[5] 1en:12 $datos[4] en $datos[4]\n";
    }
  } 
}
####### KILL ########
if (@datos[3] =~/KILL/i) {
 if ($datos[4] eq "") {
  print $socket "{numerico}AJ P $trio :Comando Incorrecto.12/msg $bot10 KILL <nick>\n";
 }
 else {
    print $socket "${numerico}AJ DBQ * o $datos[0]\n";
    defined ($text = <$socket>);
    print $socket "${numerico}AJ P $bot10 :$text\n";
    if ($text =~ 7) {
     print $socket "${numerico}AJ KILL $trio{$datos[4]} :Kill Ordenado por $datos[0]\n";
     print $socket "${numerico}AJ P $trio :Has Expulsado del IRC a: $datos[4]\n";
    }
  } 
}
######### CREDITOS #####
		if (@datos[3] =~/creditos/i) {
		foreach (@creditos) { print $socket "${numerico}AJ P $NickNumeric{lc($datos[0])} :$_\r\n"; }
		}
######### JOIN ######
		if (@datos[3] =~/join/i) {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ 5 or $text =~ 10) {
		if ($datos[4] eq "") {
                &raw("${numerico}AJ P $trio :Comando Incorrecto.12 /msg $bot10 JOIN <#Canal>");
		next;
		}
		print $socket "${numerico}AJ J $datos[4]\r\n";
            &raw("${numerico}AI P $trio :Ha Entrado en12 $datos[4]");
            &raw("${numerico}AI P $operschan :$datos[0] Ha Metido a12 $bot10 1en12 $datos[4]");
		}
            }
######### PART #######
		if (@datos[3] =~/part/i) {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ 5 or $text =~ 10) {
                if ($datos[4] eq "") {
                &raw("${numerico}AJ P $trio :Comando Incorrecto.12 /msg $bot10 PART <#Canal>");
                next;
                }
		if ($datos[4] eq $operschan) {
		&raw("${numerico}AJ P $trio :No Se Puede Salir de un 12Canal de DeBuG");
		next;
		}
                print $socket "${numerico}AJ L $datos[4]\r\n";
            &raw("${numerico}AJ P $trio :Ha Salido de12 $datos[4]");
            &raw("${numerico}AJ P $operschan :$datos[0] Ha Sacado a12 $bot10 1de12 $datos[4]");
                }
          }
######### ADDCSOP #########
		if (@datos[3] =~/addcsop/i) {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ 10) {
          if ($datos[4] eq "") {
           print $socket "{numerico}AJ P $trio :Comando Incorrecto./msg $bot10 ADDCSOP <nick>\n";
          }
          else {
 	    $serie{'o'}++;
          $serie{'v'}++;
          print $socket "$numerico DB * $serie{'o'} o $datos[4] 7\r\n";
          print $socket "$numerico DB * $serie{'v'} v $datos[4] $datos[4].CService.irc-eclipse.com\r\n";
 	    &raw("${numerico}AJ P $trio :Has a�adido a:12 $datos[4] 1de CService");
	    &raw("${numerico}AJ P $operschan :$datos[0] Ha a�adido a:12 $datos[4] 1de CService");
          }
          }
          }
######### DELCSOP #########
		if (@datos[3] =~/delcsop/i) {
         print $socket "${numerico}AJ DBQ * o $datos[0]\n";
         defined ($text = <$socket>);
         print $socket "${numerico}AJ P $bot10 :$text\n";
         if ($text =~ 10) {
          if ($datos[4] eq "") {
           print $socket "{numerico}AJ P $trio :Comando Incorrecto./msg $bot10 DELCSOP <nick>\n";
          }
          else {
 	    $serie{'o'}++;
          $serie{'v'}++;
          print $socket "$numerico DB * $serie{'o'} o $datos[4]\r\n";
          print $socket "$numerico DB * $serie{'v'} v $datos[4]\r\n";
 	    &raw("${numerico}AJ P $trio :Has eliminado a:12 $datos[4] 1de CService");
	    &raw("${numerico}AJ P $operschan :$datos[0] Ha eliminado a:12 $datos[4] 1de CService");
          }
          }
          }
}
}
#final de comandos#
}
}
print "$_";
}

