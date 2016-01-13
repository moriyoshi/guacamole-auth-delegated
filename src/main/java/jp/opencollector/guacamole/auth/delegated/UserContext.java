// Copyright (c) 2015 Open Collector, Inc.
// Copyright (c) 2015 Moriyoshi Koizumi
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package jp.opencollector.guacamole.auth.delegated;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleSecurityException;
import org.glyptodon.guacamole.form.Form;
import org.glyptodon.guacamole.net.auth.ActiveConnection;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.ConnectionRecordSet;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.Identifiable;
import org.glyptodon.guacamole.net.auth.User;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionRecordSet;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleUser;

class SingletonDirectory<T extends Identifiable> implements Directory<T> {
	private T singleton;
	private Map<String, T> singletonMap;

	public T get(String identifier) throws GuacamoleException {
		return this.singletonMap.get(identifier);
	}

	public Collection<T> getAll(Collection<String> identifiers) throws GuacamoleException {
		if (identifiers.containsAll(singletonMap.keySet())) {
			return singletonMap.values();
		}
		return Collections.<T>emptyList();
	}

	public Set<String> getIdentifiers() throws GuacamoleException {
		return singletonMap.keySet();
	}

	public void add(T object) throws GuacamoleException {
        throw new GuacamoleSecurityException("Permission denied.");
	}

	public void update(T object) throws GuacamoleException {
        throw new GuacamoleSecurityException("Permission denied.");
	}

	public void remove(String identifier) throws GuacamoleException {
        throw new GuacamoleSecurityException("Permission denied.");		
	}

	public T get() {
		return singleton;
	}

	public Collection<T> getAsCollection() {
		return singletonMap.values();
	}

	public SingletonDirectory(String identifier, T singleton) {
		this.singleton = singleton;
		this.singletonMap = Collections.singletonMap(identifier, singleton);
	}
}

public class UserContext implements org.glyptodon.guacamole.net.auth.UserContext {
	final private AuthenticationProvider provider;
	final private SingletonDirectory<ConnectionGroup> connectionGroup;
	final private SingletonDirectory<Connection> connection;
	final private SingletonDirectory<User> user;
	final private SimpleDirectory<ActiveConnection> activeConnection = new SimpleDirectory<ActiveConnection>();

	public User self() {
		return user.get();
	}

	public AuthenticationProvider getAuthenticationProvider() {
		return provider;
	}

	public Directory<User> getUserDirectory() throws GuacamoleException {
		return user;
	}

	public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
		return connection;
	}

	public Directory<ConnectionGroup> getConnectionGroupDirectory() throws GuacamoleException {
		return connectionGroup;
	}

	public Directory<ActiveConnection> getActiveConnectionDirectory() throws GuacamoleException {
		return activeConnection;
	}

	public ConnectionRecordSet getConnectionHistory() throws GuacamoleException {
		return new SimpleConnectionRecordSet();
	}

	public ConnectionGroup getRootConnectionGroup() throws GuacamoleException {
		return connectionGroup.get();
	}

	public Collection<Form> getUserAttributes() {
		return Collections.<Form>emptyList();
	}

	public Collection<Form> getConnectionAttributes() {
		return Collections.<Form>emptyList();
	}

	public Collection<Form> getConnectionGroupAttributes() {
		return Collections.<Form>emptyList();
	}

	public UserContext(AuthenticationProvider provider, String userName, AuthenticatedUser authenticatedUser) throws GuacamoleException {
		this.provider = provider;
		SimpleConnection _connection = new SimpleConnection(
			"default",
			"default",
			authenticatedUser.getConfiguration()
		);
		_connection.setParentIdentifier("ROOT");
		this.connection = new SingletonDirectory<Connection>(
			_connection.getIdentifier(),
			_connection
		);
		this.connectionGroup = new SingletonDirectory<ConnectionGroup>(
			"ROOT",
			new SimpleConnectionGroup(
				"ROOT",
				"ROOT",
				this.connection.getIdentifiers(),
				Collections.<String>emptyList()
			)
		);
		this.user = new SingletonDirectory<User>(
			userName,
			new SimpleUser(		
	            userName,
	            this.connection.getIdentifiers(),
	            connectionGroup.getIdentifiers()
            )
        );
	}
}
