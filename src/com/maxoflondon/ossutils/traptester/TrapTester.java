package com.maxoflondon.ossutils.traptester;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;
import java.net.InetAddress;
import java.util.regex.Pattern;
import java.util.Formatter;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.HashSet;
import java.util.List;
import java.util.Collection;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Scanner;
import java.util.Calendar;

public class TrapTester {
	
	public static final String EOL = "\n";
	static final Pattern ALARMDEF_PATTERN = Pattern.compile("(?:(?:\\.\\d+){12}\\.)(\\d+)(?: = )(.+)");
	static final Pattern OID_RESPONSE_PATTERN = Pattern.compile("((?:\\.\\d+)+)(?: = )(.+)");
	static final Pattern FDQN_PATTERN = Pattern.compile("(^[^.]+\\.[^.]+\\.xxx\\.xxx\\.net)");
	
	String host;
	String hostIp;
	String sysName;
	String trapCollector = "10.5.2.xxx";
	String broker = "xxxxxx";
	String iFace="";
	String readCommunity = "";
	String alarmDescription = "";
	String alarmStatusId = "";
	String extNumber = "8.0000.00";
	String severity = "1";
	String serviceAffecting = "1";
	String alarmNumber = "999999";
	String alarmStatusOn; // 1 - trigger, 2 - clear alarm
	String conditionType; // REMOTE-CCM
	boolean bInteractive = false;
	
	
	public static void main(String[] args) {
		
		Options opt = new Options(args);
		opt.addSet("RaiseAlarm", 1)
			.addOption("raise", Options.Multiplicity.ONCE)
			.addOption("i", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("hip", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("tc", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("b", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("an", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("ad", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("sa", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("en", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("aid", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("ct", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("sev", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("v", Options.Multiplicity.ZERO_OR_ONE);
		
			
		
		opt.addSet("ClearAlarm", 1)
			.addOption("clear", Options.Multiplicity.ONCE)
			.addOption("i", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("hip", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("tc", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("b", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("an", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("ad", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("sa", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("en", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("aid", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("ct", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("sev", Options.Separator.BLANK, Options.Multiplicity.ZERO_OR_ONE)
			.addOption("v", Options.Multiplicity.ZERO_OR_ONE);

		//OptionSet set = opt.getMatchingSet();
		//set = opt.getMatchingSet();
		// this did not work, a workaround below

		OptionSet set = null;

		if (opt.check("RaiseAlarm")) {
			set = opt.getSet("RaiseAlarm");
		}
		if (set == null && opt.check("ClearAlarm")) {
			set = opt.getSet("ClearAlarm");
		}
		
		// if mandatory options are missing or argument was --help print help
		if (set == null || args[0].equalsIgnoreCase("--help")) {
			printHelp();
			System.exit(-1);
		}
		
		TrapTester tt = new  TrapTester();

		/* Set interactive mode if any one is missing
		* "ad" - alarm description
		* "i" - interface 
		* "aid" - alarm status id
		*/
		if(!(set.isSet("ad") && set.isSet("aid") && set.isSet("i"))){
			tt.bInteractive = true;
		} else {
			tt.alarmDescription = set.getOption("ad").getResultValue(0);
			tt.iFace = set.getOption("i").getResultValue(0);
			tt.alarmStatusId = set.getOption("aid").getResultValue(0);
		}
		
		// "hip" hostIp - used for passive mode only and is required, for interactive mode it is ignored
		if (!tt.bInteractive && !set.isSet("hip")) {
			System.out.println("Host IP must be specified in passive run mode. Use option -hip <host>.");
			System.exit(10);
		} else if (!tt.bInteractive && set.isSet("hip")) {
			tt.hostIp = set.getOption("hip").getResultValue(0);
		}
		
		// "ct" conditionType - used for passive mode only and is required, for interactive mode it is ignored
		if (!tt.bInteractive && !set.isSet("ct")) {
			System.out.println("Condition type must be specified in passive run mode. Use option -ct <type>.");
			System.exit(11);
		} else if (!tt.bInteractive && set.isSet("ct")) {
			tt.conditionType = set.getOption("ct").getResultValue(0);
		}
		
		if (set.isSet("an")) tt.alarmNumber = set.getOption("an").getResultValue(0);
		if (set.isSet("sa")) tt.serviceAffecting = set.getOption("sa").getResultValue(0);
		if (set.isSet("en")) tt.extNumber = set.getOption("en").getResultValue(0);
		if (set.isSet("sev")) tt.severity = set.getOption("sev").getResultValue(0);

		
		// assert broker and trap collector are valid
		if (set.isSet("b")) {
			String[] b = tt.resolveHost(set.getOption("b").getResultValue(0));
			tt.broker = b[0];
		}
		if (set.isSet("tc")) {
			String[] tc = tt.resolveHost(set.getOption("tc").getResultValue(0));
			tt.trapCollector = tc[0];
		}
				
		if (set.getSetName().equals("RaiseAlarm"))
			tt.alarmStatusOn = "1";
		if (set.getSetName().equals("ClearAlarm"))
			tt.alarmStatusOn = "2";
		
		if (tt.bInteractive) {
			String[] tmp = tt.resolveHost(set.getData().get(0));
			try {
				Matcher m = FDQN_PATTERN.matcher(tmp[0]);
				if (!m.find()) {
					String host = tt.fallbackResolveHost(set.getData().get(0));
					m.reset(host);
					if (m.find()) {
						tmp[0] = m.group(1);			
					} else {
						// store input as is if passive mode
						tmp[0] = set.getData().get(0);
					}
				}
			} catch (Exception ex) {
				ex.printStackTrace();
			}
			tt.host = tmp[0];
			tt.hostIp = tmp[1];
		} else {
			tt.host = set.getData().get(0);
			tt.sysName = tt.host;
		}
		
		// the host must exist in IO3 domain for alarm to be injected
		tt.assertHostInIo3();
		
		// if interactive
		if (tt.bInteractive) {
			tt.readCommunity = tt.snmpGetReadCommunity();
			HashMap<String, HashMap<String, String>> alarms = tt.snmpGetAlarmDef();
			//print list of avail alarms
			List<String> keys = new ArrayList<String>(alarms.keySet());
			Collections.sort(keys);
			System.out.println("\nAvailable alarm condition types:");
			
			final String[] highlights = new String[] {
				"REMOTE-CCM",
				"LINK-DOWN"
			};
			for (int i = 0; i < keys.size(); i+=3) {
				String elem1 = keys.get(i);
				String elem2 = (i+1)<keys.size()?keys.get(i+1):"";
				String elem3 = (i+2)<keys.size()?keys.get(i+2):"";
				System.out.println(highlightWords(elem1, highlights, 28) + highlightWords(elem2, highlights, 28) + highlightWords(elem3, highlights, 28));
			}

			Scanner scanner = new Scanner(System.in);
			System.out.println("\033[0m");
			System.out.print("Input alarm condition type: ");
			tt.conditionType = scanner.nextLine().trim();
			
			if (! alarms.containsKey(tt.conditionType)) {
				System.out.println("Incorrect alarm entered. Alarm should be exactly as it is listed above and is case sensitive");
				System.exit(9);
			}
			
			System.out.println("\nAvailable end-points for alarm:");			
			HashMap<String, String> iface = tt.snmpGetInterfaces(alarms.get(tt.conditionType));
			List<String> ifaces = new ArrayList<String>(iface.values());
			Collections.sort(ifaces);
			for (String elem :  ifaces) {
				System.out.println(elem);
			}

			System.out.println();
			System.out.print("Input end-point: ");
			tt.iFace  = scanner.nextLine().trim();
			
			
			// get alarm id
			tt.alarmStatusId = getKeyByValue(iface, tt.iFace);
			if (tt.alarmStatusId == null) {
				System.out.println("Invalid end-point entered.End-point should be exactly as it is listed above and is case sensitive");
				System.exit(12);
			}
			tt.sysName = tt.snmpGet(".1.3.6.1.2.1.1.5.0", true);
			tt.alarmDescription = tt.snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.3."+tt.alarmStatusId, true);
			tt.extNumber = tt.snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.7."+tt.alarmStatusId, true);
			tt.severity = tt.snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.5."+tt.alarmStatusId, true);
			tt.serviceAffecting = tt.snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.6."+tt.alarmStatusId, true); //
			tt.alarmNumber = tt.snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.2."+tt.alarmStatusId, true); // 100204		
		}

		String[] cmd = tt.formCmd();
		
		String result="";
		try {
			result = execCmd(cmd);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		if (set.isSet("v")) {
			System.out.println("\nCommand executed:");
			System.out.println(tt.cmdToString(cmd));
		}
	}
	
	private String[] formCmd() {
		String[] cmd = {
				"sm_snmp",
				"-d",
				this.trapCollector,
				"trap",
				this.hostIp,
				".1.3.6.1.4.1.22420.2.1.12",
				"6",
				this.alarmStatusOn, // 1 - notify, 2 - clear
				"992691570" /*uptime*/,
				".1.3.6.1.4.1.22420.2.1.10.1.1." + alarmStatusId,
				"i",
				this.alarmStatusId,
				".1.3.6.1.4.1.22420.2.1.10.1.2." + alarmStatusId,
				"i",
				this.alarmNumber, 
				".1.3.6.1.4.1.22420.2.1.10.1.5." + alarmStatusId,
				"i",
				this.severity,  
				".1.3.6.1.4.1.22420.2.1.10.1.6." + alarmStatusId,
				"i",
				this.serviceAffecting, //Service Affecting 
				".1.3.6.1.4.1.22420.2.1.10.1.3." + alarmStatusId,
				"s",
				"[Simulated] "+ this.alarmDescription,
				".1.3.6.1.4.1.22420.2.1.11.1.4." + alarmStatusId,
				"s",
				now2VendorOveHex(), // StatusLastChange
				".1.3.6.1.4.1.22420.2.1.10.1.7." + alarmStatusId,
				"s",
				this.extNumber, // ExtNumber
				".1.3.6.1.4.1.22420.2.1.10.1.8." + alarmStatusId,
				"s",
				this.conditionType,  //Condition Type
				".1.3.6.1.4.1.22420.2.1.10.1.9." + alarmStatusId,
				"s",
				this.iFace, // AMOType
				".1.3.6.1.2.1.1.5.0", 
				"s",
				this.sysName
			};
					
			return cmd;
	}
	
	/**
	 * Executes shell command
	 * @param msg The command and it's parameters
	 * @return String response from the command
	 */	
	public static String execCmd(String[] cmd) throws java.io.IOException {
		
		String s = null;
		StringBuilder sbResult = new StringBuilder();

        try {
			ProcessBuilder pb =  new ProcessBuilder(cmd);
			Process p = pb.start();
			
            BufferedReader stdInput = new BufferedReader(new
                 InputStreamReader(p.getInputStream()));
 
            BufferedReader stdError = new BufferedReader(new
                 InputStreamReader(p.getErrorStream()));
 
            // read the output from the command
            while ((s = stdInput.readLine()) != null) {
                sbResult.append(s).append(EOL);
            }
             
            // read any errors from the attempted command
            while ((s = stdError.readLine()) != null) {
				sbResult.append(s).append(EOL);
            }
        }
        catch (final IOException e) {            
            e.printStackTrace();
        }
        return sbResult.toString();
    }
	
	private String[] resolveHost(String host) {
		String[] ret = new String[2];
		try {			
			InetAddress inetAddress = InetAddress.getByName(host);
			ret[0] = inetAddress.getCanonicalHostName();
			ret[1] = getIpAsString(inetAddress);
		} catch (java.net.UnknownHostException e) { 
			System.out.println("Unable to resove host: " + host);
			System.exit(9);
		}
		return ret;
	}
	
	private String fallbackResolveHost(String host) {
		String result="";
		String cmd[] = new String[] {
			"host",
			host
		};
		try {
			result = execCmd(cmd);
		} catch (java.io.IOException ex){}
		return result;
	}
	
	private String snmpGetReadCommunity() {
		String readCommunity="";
		String[] cmd = new String[] {
			"dmctl",
			"-b",
			this.broker,
			"-s",
			"AM-DEMARC",
			"get",
			"ICIM_UnitaryComputerSystem::" + this.host + "::ReadCommunity"
		};

		try {
			readCommunity = execCmd(cmd);
		} catch (Exception ex) {
			ex.printStackTrace();
			System.out.println("Unable to retrieve community string from device " + this.host);
			System.exit(5);
		}
		
		if (readCommunity.isEmpty() || readCommunity.contains("t@")) {
			System.out.println("Unable to retrieve community string from device " + this.host);
			System.exit(5);
		}
		return readCommunity.replaceAll("(\\r|\\n)", "");
	}
	
	
	private String snmpGet(String oid, boolean returnValueOnly) {
		String value=null;
		String[] cmd = new String[] {
			"sm_snmp",
			"-c",
			this.readCommunity,
			"-d",
			this.host,
			"get",
			oid
		};
		try {
			value = execCmd(cmd);
		} catch (Exception ex) {
			ex.printStackTrace();
			System.out.println("Unable to retrieve value for OID " + oid + " from device " + this.host);
			System.exit(6);
		}
		
		if (value.contains("t@")) {
			System.out.println("Unable to retrieve value for OID " + oid + " from device " + this.host);
			System.exit(6);
		}
		
		if (returnValueOnly) {
			try {
				Matcher m = OID_RESPONSE_PATTERN.matcher(value);
				if (m.find()) {
					value = m.group(2);
				}
			} catch (final PatternSyntaxException e) {
				// Syntax error in the regular expression
				e.printStackTrace();
				System.exit(8);
			}			
		}
		return value;
	}
	
	
	private HashMap<String, String> snmpGetInterfaces(HashMap<String, String> alarm) {
		
		List<String> ids = new ArrayList<String>(alarm.keySet());
		for (String id : ids) {

			String iface = snmpGet(".1.3.6.1.4.1.22420.2.1.10.1.9."+id, false);
			
			try {
				Matcher m = ALARMDEF_PATTERN.matcher(iface);
				while (m.find()) {
					String key = m.group(1);
					String value = m.group(2);
					alarm.put(key, value);
				}
			} catch (final PatternSyntaxException e) {
				// Syntax error in the regular expression
				e.printStackTrace();
				System.exit(8);
			}
		}
		return alarm;
	}
	
	private LinkedHashMap<String, HashMap<String, String>> snmpGetAlarmDef() {
		
		String result = "";
		
		String[] cmd = new String[] {
			"sm_snmp",
			"-c",
			readCommunity,
			"-d",
			this.host,
			"walk",
			".1.3.6.1.4.1.22420.2.1.10.1.8"
		};

		try {
			result = execCmd(cmd);
		} catch (Exception ex) {
			ex.printStackTrace();
			System.out.println("Unable to retrieve alarm definition from device " + this.host);
			System.exit(6);
		}
		
		if (result.contains("t@")) {
			// .1.3.6.1.4.1.22420.2.1.10.1.8.56 = LINK-DOWN
			System.out.println("Unable to retrieve alarm definition from device " + this.host);
			System.exit(6);
		}
		
		LinkedHashMap<String, HashMap<String, String>> alarms = new LinkedHashMap<String, HashMap<String, String>>();
		BufferedReader bufReader = new BufferedReader(new StringReader(result));
		
		String line=null;
		try {
			while((line=bufReader.readLine()) != null ) {
				if (line.contains("=")) {
					try {
						Matcher m = ALARMDEF_PATTERN.matcher(line);
						while (m.find()) {
							final String id = m.group(1);
							String txt = m.group(2);
							
							if (! alarms.containsKey(txt)) { 
								// key doesn't exist
								alarms.put(txt, new HashMap<String, String>() {{put(id, "");}});
							} else {
								alarms.get(txt).put(id, "");
							}						
						}
					} catch (final PatternSyntaxException e) {
						// Syntax error in the regular expression
						e.printStackTrace();
						System.exit(7);
					}
				}
			}
		} catch (java.io.IOException e) { 
			System.out.println("Unable to retrieve alarm definition from device " + this.host);
			System.exit(7);		
		}
		
		return alarms;	
	}
	
	private void assertHostInIo3() {
		String result = "";
		String[] cmd = new String[] {
			"dmctl", 
			"-b",
			this.broker,
			"-s",
			"OI3",
			"get",
			"ICIM_UnitaryComputerSystem::" + this.host + "::Name"
		};

		try {
			result = execCmd(cmd);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		if (Pattern.compile(this.host, Pattern.CASE_INSENSITIVE + Pattern.LITERAL).matcher(result).find())
			result = result.replaceAll("(\\r|\\n)", "");
		
		if (! this.host.equalsIgnoreCase(result)) {
			System.out.println(this.host + " not found in OI3");
			System.exit(2);
		}		
	}
	
	
	private static String getKeyByValue(HashMap<String, String> map, String value) {
		String key=null;
		
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (entry.getValue().equals(value)) {
				key = entry.getKey();
				break;
            }
        }
		return key;
	}
	
	private static String getIpAsString(InetAddress address) {
		byte[] ipAddress = address.getAddress();
		StringBuffer str = new StringBuffer();
		for(int i=0; i<ipAddress.length; i++) {
			if(i > 0) str.append('.');
			str.append(ipAddress[i] & 0xFF);				
		}
		return str.toString();
	}	
	
	private static String highlightWords(String input, String[] words, int pad) {
		String result =  "\u001B[0m" + input;
		
		for (String word : words) {
			if (input.equals(word)) {
				result = "\033[1m" + word; //"\u001B[7m" + word ;
				break;
			}
		}
		
		int len = result.length();
		while (pad - len > 0) {
			result +=" ";
			pad--;
		}
		return result;
	}
	
	private String cmdToString(String[] cmd) {
		StringBuilder sb = new StringBuilder();
		String prefix = "";
		for (String s : cmd) {
			if (s.matches(".*[ |:].*")) 
				sb.append(prefix).append("\"").append(s).append("\"");
			else
				sb.append(prefix).append(s);
			prefix = " ";
		}
		
		return sb.toString();
	}
	
   private static String vendoeOveHex2AsciiDate(String s) {
                  s = s.replace(" ", "");
                  String year = String.format("%04d", Integer.parseInt(s.substring(0, 4), 16));
                  String month = String.format("%02d", Integer.parseInt(s.substring(4, 6), 16));
                  String day = String.format("%02d", Integer.parseInt(s.substring(6, 8), 16));
                  String hour = String.format("%02d", Integer.parseInt(s.substring(8, 10), 16));
                  String min = String.format("%02d", Integer.parseInt(s.substring(10, 12), 16));
                  String sec = String.format("%02d", Integer.parseInt(s.substring(12, 14), 16));
                  return year + "-" + month + "-" + day + " " + hour + ":" + min + ":" + sec;
   }
   
   private static String now2VendorOveHex() {
                  String[] dateHex = {
                                 innerPadHex(padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.YEAR)), 4)),
                                 padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.MONTH)), 2),
                                 padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.DAY_OF_MONTH)), 2),
                                 padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.HOUR)), 2),
                                 padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.MINUTE)), 2),
                                 padHex(Integer.toHexString(Calendar.getInstance().get(Calendar.SECOND)), 2),
                                 "00 2B 00 00"
                  };
                  String prefix = "";
                  StringBuilder sb = new StringBuilder();
                  for (String s : dateHex) {
                                 sb.append(prefix).append(s);
                                 prefix = " ";
                  }  
                  return sb.toString();
   }
   
   private static String padHex(String s, int length) {
                              String zeroMask = new String(new char[length]).replace("\0", "0");
                              return (zeroMask.substring(s.length()) + s).toUpperCase();
   }
   
   private static String innerPadHex(String s) {
                  return s.substring(0, 2) + " " + s.substring(2);
   }
	
	
	private static void printHelp() {
		String[] help = {
			"\033[1mTrapsim v1.1\033[0m ",
			"Simulate SNMP v2c trap into Smarts for Overture/Accedian device.",
			"",
			"Usage: java -jar trapsim.jar -command [-options] host",
			"",
			"where command include:",
			"    -clear            dispatch alarm clear event",
			"    -raise            dispatch alarm raise event    ",
			"    --help            display this help",
			"",
			"where options inclide:",
			"    -ad             Alarm description (acdAlarmCfgDesc), mandatory for exe-",
			"                    cution in passive mode and ignored in interactive mode",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.3.<alarmStatusId>",
			"                    example: SFP-B receive power low warning",
			"",
			"    -aid            Alarm status id (acdAlarmCfgID), mandatory for execution",
			"                    in passive mode",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.1.<alarmStatusId>",
			"                    example: 51, 71",
			"",
			"    -an             Alarm number (acdAlarmCfgNumber), mandatory for execution ",
			"                    in passive mode and    ignored in interactive mode",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.2.<alarmStatusId>",
			"                    example: 400207, 200209",
			"",
			"    -b              Smarts broker, optinal",
			"                    The default is sma0.lon",
			"                        ",
			"    -ct             Condition type (acdAlarmCfgConditionType), mandatory for ",
			"                    execution in passive mode",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.8.<alarmStatusId>",
			"                    example: TX-PWR-HIGH-ALM, LINK-DOWN",
			"",
			"    -en             (acdAlarmCfgExtNumber), optional in passive mode and ignored",
			"                    in interactive mode",
			"                    The default is 8.0000.00",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.7.<alarmStatusId>",
			"                    example: 8.0001.41, 2.0002.04",
			"",
			"    -hip            Host IP address, mandatory for execution in passive mode",
			"                    and ignored in interactive mode",
			"                        ",
			"    -i              Interface (acdAlarmCfgAMOType), mandatory for execution",
			"                    in passive mode and ignored in interactive mode",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.9.<alarmStatusId>",
			"                    example: SFP.1, PORT.PORT-4",
			"",
			"    -sa             Service affecting (acdAlarmCfgServiceAffecting), optional ",
			"                    in passsive mode and ignored in    interactive mode",
			"                    The default is 1",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.6.<alarmStatusId>",
			"                    example: 1, 2",
			"",
			"    -sev            Severity (acdAlarmCfgSeverity), optional in passive mode and",
			"                    ignored in interactive mode",
			"                    The default is 1",
			"                    value of oid .1.3.6.1.4.1.22420.2.1.10.1.5.<alarmStatusId>",
			"                    Example: 0, 3",
			"",
			"    -tc             Trap collector to use, optional ",
			"                    The default is 10.5.2.xxx",
			"",
			"    -v              Verbose - print executed command, optional",
			"",
			"where parameter is:",
			"    host            FQDN of Overture/Accedian device",
			"",
			"Usage examples:",
			"",
			"Interactive mode:",
			"java -jar trapsim.jar -raise -b $BROKER -tc $TRAPCOLLECTOR 01341.xxx.xxx.xxx.net",
			"",
			"Passive mode with mandatory options only:",
			"java -jar trapsim.jar -raise -ad \"Remote CCM on down MEP, MEPID 1111, port Network, level 3\" -aid 100 -an 400103 -ct REMOTE-CCM -hip 10.183.164.35 -i CFM.ACCESS-GVA/ZRH/LE-126169_A-CH:110901547.1111.Network.3.down.0 FRA_CA_01341.lanlink.dcn.colt.net",
			"",
			"Passive mode with optional options:",
			"java -jar trapsim.jar -raise -b $BROKER -tc $TRAPCOLLECTOR -ad \"Remote CCM on down MEP, MEPID 1111, port Network, level 3\" -aid 100 -an 400103 -ct REMOTE-CCM -hip 10.183.164.35 -i CFM.ACCESS-GVA/ZRH/LE-126169_A-CH:110901547.1111.Network.3.down.0 -sev 1 -sa 2 -en 4.001.03 GMB_ET_00002_07.lanlink.dcn.colt.net",
			"",
			"Prerequisites:",
			"Simulator must be run from Smarts server where paths to sm_snmp and dmctl are ",
			"defined.",
			"The device must be discovered and present in OI3 domain.",
			"",
			"Disclaimer",
			"THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR",
			"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FIT-",
			"NESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE",
			"MAX GURDZIEL BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER",
			"IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CON-",
			"NECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE"
		};
		
		StringBuilder sb = new StringBuilder();
		for (String s : help) {
			sb.append(s).append("\n");
		}
		
		System.out.println(sb.toString());
	}
}
