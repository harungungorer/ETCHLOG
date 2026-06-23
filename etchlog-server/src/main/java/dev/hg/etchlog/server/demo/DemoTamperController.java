package dev.hg.etchlog.server.demo;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Base64;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DEMO-ONLY tamper affordance for the verification dashboard. Mounted only under the {@code demo}
 * Spring profile; absent (and {@code denyAll}-blocked) otherwise. NOT part of the public API.
 *
 * @see DemoTamperService
 * @see <a
 *     href="../../../../../../../../docs/features/VERIFICATION_DASHBOARD.md">VERIFICATION_DASHBOARD.md</a>
 */
@RestController
@Profile("demo")
@RequestMapping("/api/v1/_demo")
@Tag(
        name = "Demo (tamper)",
        description =
                "DEV/DEMO ONLY. Rewrites a stored leaf directly in the database to demonstrate"
                        + " tamper detection. Disabled unless the server runs with the demo"
                        + " profile.")
public class DemoTamperController {

    private final DemoTamperService tamperService;

    public DemoTamperController(DemoTamperService tamperService) {
        this.tamperService = tamperService;
    }

    @Operation(
            summary = "Tamper a stored leaf (demo only)",
            description =
                    "Mutates the leaf at the given index in the database (payload, leaf hash, and"
                            + " its level-0 tree node), leaving the signed tree heads intact. The"
                            + " next in-browser verification then fails — the headline"
                            + " tamper-evidence demo.")
    @PostMapping(path = "/tamper/{index}", produces = MediaType.APPLICATION_JSON_VALUE)
    public TamperResponse tamper(@PathVariable("index") long index) {
        DemoTamperService.TamperResult result = tamperService.tamper(index);
        return TamperResponse.from(result);
    }

    /** Response describing what the leaf was tampered to (Base64-encoded, like the entry API). */
    public record TamperResponse(long leafIndex, String tamperedLeafData, String tamperedLeafHash) {

        static TamperResponse from(DemoTamperService.TamperResult r) {
            Base64.Encoder b64 = Base64.getEncoder();
            return new TamperResponse(
                    r.leafIndex(),
                    b64.encodeToString(r.tamperedPayload()),
                    b64.encodeToString(r.tamperedLeafHash()));
        }
    }
}
