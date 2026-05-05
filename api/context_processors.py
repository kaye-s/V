def session_user(request):
    """Expose logged-in session email for nav/sidebar templates."""
    theme = "dark"
    user_id = request.session.get("user_id")
    if user_id:
        try:
            from .models import UserSetting

            theme = UserSetting.objects.filter(user_id=user_id).values_list("theme", flat=True).first() or theme
        except Exception:
            theme = "dark"
    return {
        "user_email": request.session.get("user_email") or "",
        "user_name": request.session.get("user_name") or "",
        "user_department": request.session.get("department") or "",
        "user_role": request.session.get("user_role") or "",
        "user_theme": theme,
    }
