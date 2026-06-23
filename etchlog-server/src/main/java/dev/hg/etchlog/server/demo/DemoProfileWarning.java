package dev.hg.etchlog.server.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * DEMO-ONLY: emits a loud, unmissable startup banner whenever the {@code demo} profile is active.
 *
 * <p>The {@code demo} profile mounts the <strong>unauthenticated</strong> {@code POST
 * /api/v1/_demo/tamper/{index}} endpoint (see {@link DemoTamperController} / {@link
 * DemoTamperService}), which rewrites committed log records in place. That is intentional for the
 * local tamper-evidence demo, but catastrophic if the profile is ever left active on a reachable
 * deployment: anyone who can reach the endpoint can silently corrupt the log.
 *
 * <p>A hard startup refusal is deliberately <em>not</em> used here, because {@code demo} is
 * documented as combinable with the {@code postgres} profile for a Postgres-backed demo
 * (application-demo.yml), so "demo + production-style datasource" is not by itself a reliable
 * misconfiguration signal. Instead this guard makes the exposure impossible to miss in the logs —
 * defense-in-depth alongside the {@code @Profile("demo")} gating on the controller, service, and
 * permissive security chain, and the main chain's {@code denyAll} fallback when the profile is off.
 *
 * @see DemoTamperController
 * @see DemoSecurityConfig
 */
@Component
@Profile("demo")
public class DemoProfileWarning {

    private static final Logger log = LoggerFactory.getLogger(DemoProfileWarning.class);

    @EventListener(ApplicationReadyEvent.class)
    public void warnOnStartup() {
        log.warn(
                """

                ************************************************************************
                *  ETCHLOG 'demo' PROFILE IS ACTIVE — DO NOT EXPOSE THIS SERVER.      *
                *                                                                    *
                *  The UNAUTHENTICATED endpoint                                      *
                *      POST /api/v1/_demo/tamper/{index}                             *
                *  is mounted. It rewrites committed log records directly in the     *
                *  database to demonstrate tamper-evidence. Anyone who can reach it  *
                *  can silently corrupt your log.                                    *
                *                                                                    *
                *  Run WITHOUT the 'demo' profile for any non-local deployment.      *
                ************************************************************************""");
    }
}
