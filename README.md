# passcheck

To Do:
	-	Define password policy interface; implementations should define at least one method which will return a boolean
		indicating whether a supplied password meets the policy requirements. 
		-	Maybe this is what PassCheckConfig should *actually* do.
		-	Possibly define some base/common methods in the interface or an abstract base class (like minLength, etc.) 
			and then add an interface method like 'private boolean doExtraChecks(String password)' where more complex 
			logic can be defined
	