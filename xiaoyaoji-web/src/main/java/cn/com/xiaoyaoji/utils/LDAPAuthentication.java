/**  
 * @Title:  LdapUtil.java   
 * @Package cn.com.xiaoyaoji.utils   
 * @Description:    TODO(用一句话描述该文件做什么)   
 * @author: 3氵哥     
 * @date:   2018年11月17日 下午3:45:40   
 * @version V1.0  
 */
package cn.com.xiaoyaoji.utils;

import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class LDAPAuthentication {
	private final String URL = "ldap://47.107.185.134:389/";
	private final String BASEDN = "dc=example,dc=org"; // 根据自己情况进行修改
	private final String FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
	private LdapContext ctx = null;
	private final Control[] connCtls = null;

	private void LDAP_connect() {
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, FACTORY);
		env.put(Context.PROVIDER_URL, URL + BASEDN);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");

		String root = "cn=admin,dc=example,dc=org"; // 根据自己情况修改
		env.put(Context.SECURITY_PRINCIPAL, root); // 管理员
		env.put(Context.SECURITY_CREDENTIALS, "admin"); // 管理员密码

		try {
			ctx = new InitialLdapContext(env, connCtls);
			System.out.println("连接成功");

		} catch (javax.naming.AuthenticationException e) {
			System.out.println("连接失败：");
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("连接出错：");
			e.printStackTrace();
		}

	}

	private void closeContext() {
		if (ctx != null) {
			try {
				ctx.close();
			} catch (NamingException e) {
				e.printStackTrace();
			}

		}
	}

	private String getUserDN(String uid) {
		String userDN = "";
		LDAP_connect();
		try {
			SearchControls constraints = new SearchControls();
			constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
			
			String returnedAtts[] = { "uid,email,cn,distinguishedName" };// 定制返回属性
			constraints.setReturningAttributes(returnedAtts); // 设置返回属性集
			
			NamingEnumeration<SearchResult> en = ctx.search("", "uid=" + uid, constraints);

			if (en == null || !en.hasMoreElements()) {
				System.out.println("未找到该用户");
			}
			// maybe more than one element
			while (en != null && en.hasMoreElements()) {
				Object obj = en.nextElement();
				if (obj instanceof SearchResult) {
					SearchResult si = (SearchResult) obj;
					userDN += si.getName();
					userDN += "," + BASEDN;
				} else {
					System.out.println(obj);
				}
			}
		} catch (Exception e) {
			System.out.println("查找用户时产生异常。");
			e.printStackTrace();
		}

		return userDN;
	}

	public boolean authenricate(String UID, String password) {
		boolean valide = false;
		String userDN = getUserDN(UID);

		try {
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDN);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
			ctx.reconnect(connCtls);
			System.out.println(userDN + " 验证通过");
			valide = true;
		} catch (AuthenticationException e) {
			System.out.println(userDN + " 验证失败");
			System.out.println(e.toString());
			valide = false;
		} catch (NamingException e) {
			System.out.println(userDN + " 验证失败");
			valide = false;
		}
		closeContext();
		return valide;
	}

	private boolean addUser(String usr, String pwd) {

		try {
			LDAP_connect();
			BasicAttributes attrsbu = new BasicAttributes();
			BasicAttribute objclassSet = new BasicAttribute("objectclass");
			objclassSet.add("inetOrgPerson");
			attrsbu.put(objclassSet);
			attrsbu.put("sn", usr);
			attrsbu.put("cn", usr);
			attrsbu.put("uid", usr);
			attrsbu.put("userPassword", pwd);
			ctx.createSubcontext("uid=yorker", attrsbu);

			return true;
		} catch (NamingException ex) {
			ex.printStackTrace();
		}
		closeContext();
		return false;
	}

	public static void main(String[] args) {
		LDAPAuthentication ldap = new LDAPAuthentication();

		// ldap.LDAP_connect();

		if (ldap.authenricate("majintao", "123456") == true) {

			System.out.println("该用户认证成功");

		}
		// ldap.addUser("yorker","secret");

	}
}
