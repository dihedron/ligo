// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/** A JwtSvidSource that makes an unsigned JWT-SVID for the audience and records who asked for what. */
class FakeJwt implements JwtSvidSource {
    record Call(String audience, SpiffeId subject) {}

    final List<Call> calls = new CopyOnWriteArrayList<>();

    static String token(String audience, String subject) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString("{\"alg\":\"ES256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String claims = b64.encodeToString(("{\"sub\":\"" + subject + "\",\"aud\":[\"" + audience + "\"],\"exp\":4102444800}")
                .getBytes(StandardCharsets.UTF_8));
        return header + "." + claims + "." + b64.encodeToString("sig".getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public JwtSvid fetchJwtSvid(String audience, String... extra) throws JwtSvidException {
        return fetchJwtSvid(SpiffeId.parse(ClientTest.WORKER_ID), audience, extra);
    }

    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extra) throws JwtSvidException {
        calls.add(new Call(audience, subject));
        return JwtSvid.parseInsecure(token(audience, subject.toString()), Set.of(audience));
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extra) throws JwtSvidException {
        return List.of(fetchJwtSvid(audience, extra));
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extra) throws JwtSvidException {
        return List.of(fetchJwtSvid(subject, audience, extra));
    }
}
