<?php
/*
* PHP-SNMP Demo file
* @author: Alexandre Levavasseur
*/

/*
 Some docs
 http://stackoverflow.com/questions/29945243/using-pysnmp-traps-to-update-nagios-services-status
 1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.4.1.20006.1.7
 http://www.circitor.fr/Mibs/Html/NAGIOS-NOTIFY-MIB.php#nHostEvent
 nHostEvent      1.3.6.1.4.1.20006.1.5
 nHostname       1.3.6.1.4.1.20006.1.1.1.2
 nHostStateID    1.3.6.1.4.1.20006.1.1.1.4   0=UP, 1=DOWN, 2=UNREACHABLE.
 nHostLastChange 1.3.6.1.4.1.20006.1.1.1.10
*/

// Load class
require_once('PHP_SNMP.php');

// Header
$target = '198.51.100.3';
$communit = 'ctestc';
$TrapOId = "1.3.6.1.4.1.20006.1.5";

// Content
$vars[] = array('oid' => '1.3.6.1.4.1.20006.1.1.1.2', 'value' => 'AP-12345', 'type' => 's');
$vars[] = array('oid' => '1.3.6.1.4.1.20006.1.1.1.4', 'value' => 0, 'type' => 'i');
$vars[] = array('oid' => '1.3.6.1.4.1.20006.1.1.1.10', 'value' => '1437399888', 'type' => 'c');

// Send trap
PHP_SNMP::trap($target, $vars, $community, $TrapOId);

?>
