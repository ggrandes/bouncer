package org.javastack.bouncer.jmx;

import static java.lang.annotation.ElementType.*;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({
		CONSTRUCTOR, METHOD, PARAMETER, TYPE
})
public @interface Description {
	String value();
}
