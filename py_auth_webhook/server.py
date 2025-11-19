from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple authorization rules
# Format: {namespace: {resource: [allowed_verbs]}}
AUTHORIZATION_RULES = {
    "default": {
        "pods": ["get", "list", "watch"],
        "services": ["get", "list"],
    },
    "production": {
        "pods": ["get", "list", "watch"],
        "deployments": ["get", "list"],
    },
    "development": {
        "pods": ["*"],  # All verbs allowed
        "deployments": ["*"],
        "services": ["*"],
    }
}

# Admin users who have full access
ADMIN_USERS = ["admin", "system:masters"]

@app.route('/authorize', methods=['POST'])
def authorize():
    """
    Handle authorization requests from Kubernetes API server.
    
    Request format (SubjectAccessReview):
    {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "resourceAttributes": {
                "namespace": "default",
                "verb": "get",
                "resource": "pods"
            },
            "user": "jane",
            "groups": ["developers"]
        }
    }
    """
    try:
        body = request.get_json()
        
        # Extract request details
        spec = body.get('spec', {})
        user = spec.get('user', '')
        groups = spec.get('groups', [])
        resource_attrs = spec.get('resourceAttributes', {})
        
        namespace = resource_attrs.get('namespace', '')
        verb = resource_attrs.get('verb', '')
        resource = resource_attrs.get('resource', '')
        
        logger.info(f"Authorization request - User: {user}, Namespace: {namespace}, "
                   f"Verb: {verb}, Resource: {resource}")
        
        # Check if user is admin
        if user in ADMIN_USERS or any(g in ADMIN_USERS for g in groups):
            logger.info(f"Admin user {user} - allowing access")
            return create_response(True, "Admin access granted")
        
        # Check namespace-based rules
        if namespace in AUTHORIZATION_RULES:
            ns_rules = AUTHORIZATION_RULES[namespace]
            
            if resource in ns_rules:
                allowed_verbs = ns_rules[resource]
                
                # Check if all verbs are allowed or specific verb is in the list
                if "*" in allowed_verbs or verb in allowed_verbs:
                    logger.info(f"Access granted for {user} to {verb} {resource} in {namespace}")
                    return create_response(True, f"Access granted by rule")
                else:
                    logger.info(f"Access denied - verb {verb} not allowed")
                    return create_response(False, f"Verb '{verb}' not allowed for resource '{resource}'")
            else:
                logger.info(f"Access denied - resource {resource} not in rules")
                return create_response(False, f"No rules defined for resource '{resource}'")
        else:
            logger.info(f"Access denied - namespace {namespace} not in rules")
            return create_response(False, f"No rules defined for namespace '{namespace}'")
            
    except Exception as e:
        logger.error(f"Error processing authorization request: {str(e)}")
        return create_response(False, f"Internal error: {str(e)}")

def create_response(allowed, reason):
    """Create a SubjectAccessReview response."""
    return jsonify({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "status": {
            "allowed": allowed,
            "reason": reason
        }
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    # In production, use a proper WSGI server like gunicorn
    # and enable HTTPS with proper certificates
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')
