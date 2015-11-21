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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.io.IOContext;
import com.fasterxml.jackson.core.json.ReaderBasedJsonParser;
import com.fasterxml.jackson.core.json.UTF8StreamJsonParser;
import com.fasterxml.jackson.core.util.BufferRecycler;
import com.fasterxml.jackson.core.sym.ByteQuadsCanonicalizer;
import com.fasterxml.jackson.core.sym.CharsToNameCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.base.Optional;
import com.google.common.net.MediaType;

public class DelegatedAuthenticationProvider implements AuthenticationProvider {
	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final ByteQuadsCanonicalizer byteSymbolCanonicalizer = ByteQuadsCanonicalizer.createRoot();
	private static final CharsToNameCanonicalizer symbolCanonicalizer = CharsToNameCanonicalizer.createRoot();
	public String getIdentifier() {
		return "delegated";
	}

	public org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
		final Optional<GuacamoleConfiguration> config = buildConfigurationFromRequest(credentials.getRequest());
		if (!config.isPresent())
			return null;
		return new AuthenticatedUser(this, "delegated", credentials, config.get());
	}

	public org.glyptodon.guacamole.net.auth.AuthenticatedUser updateAuthenticatedUser(org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticatedUser, Credentials credentials)
			throws GuacamoleException {
        return authenticatedUser;
	}

	public org.glyptodon.guacamole.net.auth.UserContext getUserContext(org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticatedUser) throws GuacamoleException {
		return new UserContext(this, "delegated", (AuthenticatedUser)authenticatedUser);
	}

	public org.glyptodon.guacamole.net.auth.UserContext updateUserContext(org.glyptodon.guacamole.net.auth.UserContext context, org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticatedUser)
			throws GuacamoleException {
        return context;
	}

	private static JsonParser createJsonParser(InputStream is, Charset charset, ObjectCodec codec) {
		final IOContext ctxt = new IOContext(new BufferRecycler(), is, false);
		if (charset.equals(UTF_8)) {
			final byte[] buf = ctxt.allocReadIOBuffer();
			return new UTF8StreamJsonParser(
				ctxt, 0, is,
				codec,
				byteSymbolCanonicalizer.makeChild(
					JsonFactory.Feature.CANONICALIZE_FIELD_NAMES.getMask()
				),
				buf, 0, 0,
				true
			);
		} else {
			return new ReaderBasedJsonParser(
				ctxt, 0,
				new InputStreamReader(is, charset),
				codec,
				symbolCanonicalizer.makeChild(
					JsonFactory.Feature.CANONICALIZE_FIELD_NAMES.getMask()
				)
			);
		}
	}

	private static Optional<GuacamoleConfiguration> buildConfigurationFromRequest(HttpServletRequest req) throws GuacamoleException {
		try {
			if (req.getClass().getName().equals("org.glyptodon.guacamole.net.basic.rest.APIRequest")) {
				final GuacamoleConfiguration config = new GuacamoleConfiguration();
				final String protocol = req.getParameter("protocol");
				if (protocol == null)
					throw new GuacamoleException("required parameter \"protocol\" is missing");
				config.setProtocol(protocol);
				for (Map.Entry<String, String[]> param: req.getParameterMap().entrySet()) {
					String[] values = param.getValue();
					if (values.length > 0)
						config.setParameter(param.getKey(), values[0]);
				}
				return Optional.of(config);
			} else {
				final ServletInputStream is = req.getInputStream();
				if (!is.isReady()) {
					MediaType contentType = MediaType.parse(req.getContentType());
					boolean invalidContentType = true;
					if (contentType.type().equals("application")) {
						if (contentType.subtype().equals("json")) {
							invalidContentType = false;
						} else if (contentType.subtype().equals("x-www-form-urlencoded") && req.getParameter("token") != null) {
							return Optional.<GuacamoleConfiguration>absent();
						}
					}
					if (invalidContentType)
						throw new GuacamoleException(String.format("expecting application/json, got %s", contentType.withoutParameters()));
					final GuacamoleConfiguration config = new GuacamoleConfiguration();
					try {
						final ObjectMapper mapper = new ObjectMapper();
						JsonNode root = (JsonNode)mapper.readTree(createJsonParser(req.getInputStream(), contentType.charset().or(UTF_8), mapper));
						{
							final JsonNode protocol = root.get("protocol");
							if (protocol == null)
								throw new GuacamoleException("required parameter \"protocol\" is missing");
							final JsonNode parameters = root.get("parameters");
							if (parameters == null)
								throw new GuacamoleException("required parameter \"parameters\" is missing");
							config.setProtocol(protocol.asText());
							{
								for (Iterator<Entry<String, JsonNode>> i = parameters.fields(); i.hasNext();) {
									Entry<String, JsonNode> member = i.next();
									config.setParameter(member.getKey(), member.getValue().asText());
								}
							}
						}
					} catch (ClassCastException e) {
						throw new GuacamoleException("error occurred during parsing configuration", e);
					}
					return Optional.of(config);
				} else {
					return Optional.<GuacamoleConfiguration>absent();
				}
			}
		} catch (IOException e) {
			throw new GuacamoleException("error occurred during retrieving configuration from the request body", e);
		}
	}

	public DelegatedAuthenticationProvider() throws GuacamoleException {}
}
