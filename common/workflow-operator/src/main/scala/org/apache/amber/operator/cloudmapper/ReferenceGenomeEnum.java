package org.apache.amber.operator.cloudmapper;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ReferenceGenomeEnum {
    HUMAN_GRCh38("GRCh38"),

    MOUSE_GRCm39("GRCm39"),

    MOUSE_mm10("mm10"),

    HUMAN_hg19("hg19"),

    MY_REFERENCE("My Reference");

    private final String name;

    ReferenceGenomeEnum(String name) {
        this.name = name;
    }

    @JsonValue
    public String getName() {
        return this.name;
    }

    // Deserialize from the @JsonValue label (e.g. "GRCh38"). Required because
    // Dropwizard's FuzzyEnumModule otherwise matches on the constant name
    // (HUMAN_GRCh38) and ignores @JsonValue, breaking operator deserialization.
    @JsonCreator
    public static ReferenceGenomeEnum fromValue(String value) {
        for (ReferenceGenomeEnum genome : values()) {
            if (genome.name.equals(value)) {
                return genome;
            }
        }
        throw new IllegalArgumentException("Unknown reference genome: " + value);
    }
}