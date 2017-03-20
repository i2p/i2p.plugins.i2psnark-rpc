/*
 * File    : WebPlugin.java
 * Created : 23-Jan-2004
 * By      : parg
 * 
 * Azureus - a Java Bittorrent client
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details ( see the LICENSE file ).
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.klomp.snark.rpc;

/**
 * @author parg
 *
 */

public class 
WebPlugin
{
	public static final String	PR_ENABLE					= "Enable";						// Boolean
	public static final String	PR_DISABLABLE				= "Disablable";					// Boolean
	public static final String	PR_PORT						= "Port";						// Integer
	public static final String	PR_BIND_IP					= "Bind IP";					// String
	public static final String	PR_ROOT_RESOURCE			= "Root Resource";				// String
	public static final String 	PR_HOME_PAGE				= "Home Page";					// String
	public static final String	PR_ROOT_DIR					= "Root Dir";					// String
	public static final String	PR_ACCESS					= "Access";						// String
	public static final String	PR_LOG						= "DefaultLoggerChannel";		// LoggerChannel
	public static final String	PR_CONFIG_MODEL_PARAMS		= "DefaultConfigModelParams";	// String[] params to use when creating config model
	public static final String	PR_CONFIG_MODEL				= "DefaultConfigModel";			// BasicPluginConfigModel
	public static final String	PR_VIEW_MODEL				= "DefaultViewModel";			// BasicPluginViewModel
	public static final String	PR_HIDE_RESOURCE_CONFIG		= "DefaultHideResourceConfig";	// Boolean
	public static final String	PR_ENABLE_KEEP_ALIVE		= "DefaultEnableKeepAlive";		// Boolean
	public static final String	PR_PAIRING_SID				= "PairingSID";					// String
	public static final String	PR_NON_BLOCKING				= "NonBlocking";				// Boolean
	public static final String	PR_ENABLE_PAIRING			= "EnablePairing";				// Boolean
	public static final String	PR_ENABLE_I2P				= "EnableI2P";					// Boolean
	public static final String	PR_ENABLE_TOR				= "EnableTor";					// Boolean
	public static final String	PR_ENABLE_UPNP				= "EnableUPNP";					// Boolean
	
	public static final String	PROPERTIES_MIGRATED		= "Properties Migrated";
	public static final String	CONFIG_MIGRATED			= "Config Migrated";
	public static final String	PAIRING_MIGRATED		= "Pairing Migrated";
	public static final String	PAIRING_SESSION_KEY		= "Pairing Session Key";

	public static final String	CONFIG_PASSWORD_ENABLE			= "Password Enable";
	public static final boolean	CONFIG_PASSWORD_ENABLE_DEFAULT	= false;
	
	public static final String	CONFIG_PAIRING_ENABLE			= "Pairing Enable";
	public static final boolean	CONFIG_PAIRING_ENABLE_DEFAULT	= true;

	public static final String	CONFIG_PORT_OVERRIDE			= "Port Override";
	
	public static final String	CONFIG_PAIRING_AUTO_AUTH			= "Pairing Auto Auth";
	public static final boolean	CONFIG_PAIRING_AUTO_AUTH_DEFAULT	= true;

	
	public static final String	CONFIG_ENABLE					= PR_ENABLE;
	public  			boolean	CONFIG_ENABLE_DEFAULT			= true;
	
	public static final String	CONFIG_USER						= "User";
	public static final String	CONFIG_USER_DEFAULT				= "";
	
	public static final String	CONFIG_PASSWORD					= "Password";
	public static final byte[]	CONFIG_PASSWORD_DEFAULT			= {};
	
	public static final String 	CONFIG_PORT						= PR_PORT;
	public int			 		CONFIG_PORT_DEFAULT				= 8089;
	
	public static final String 	CONFIG_BIND_IP					= PR_BIND_IP;
	public String		 		CONFIG_BIND_IP_DEFAULT			= "";

	public static final String 	CONFIG_PROTOCOL					= "Protocol";
	public static final String 	CONFIG_PROTOCOL_DEFAULT			= "HTTP";

	public static final String	CONFIG_UPNP_ENABLE				= "UPnP Enable";
	public 				boolean	CONFIG_UPNP_ENABLE_DEFAULT		= true;

	public static final String 	CONFIG_HOME_PAGE				= PR_HOME_PAGE;
	public  		 String 	CONFIG_HOME_PAGE_DEFAULT		= "index.html";
	
	public static final String 	CONFIG_ROOT_DIR					= PR_ROOT_DIR;
	public        		String 	CONFIG_ROOT_DIR_DEFAULT			= "";
	
	public static final String 	CONFIG_ROOT_RESOURCE			= PR_ROOT_RESOURCE;
	public              String 	CONFIG_ROOT_RESOURCE_DEFAULT	= "";
	
	public static final String 	CONFIG_MODE						= "Mode";
	public static final String 	CONFIG_MODE_FULL				= "full";
	public static final String 	CONFIG_MODE_DEFAULT				= CONFIG_MODE_FULL;
	
	public static final String 	CONFIG_ACCESS					= PR_ACCESS;
	public        		String 	CONFIG_ACCESS_DEFAULT			= "all";
	
	protected static final String	NL			= "\r\n";
	
	protected static final String[]		welcome_pages = { "index.html", "index.htm", "index.php", "index.tmpl" };
}
