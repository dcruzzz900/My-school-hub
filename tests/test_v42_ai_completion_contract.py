from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ai_output_authorization_closes_connection_after_check():
    text = (ROOT / 'app.py').read_text()
    start = text.index('@app.route("/ai/output/<int:output_id>")')
    end = text.index('@app.route("/ai/output/<int:output_id>/review"', start)
    block = text[start:end]
    assert 'if not out:' in block
    assert 'conn.close()' in block
    assert 'return render_template("ai_output.html"' in block


def test_parent_consent_route_is_school_scoped():
    text = (ROOT / 'app.py').read_text()
    assert '@app.route("/parent/ai-consent/<int:student_id>"' in text
    assert 'parent_child(conn,session["parent_id"],student_id)' in text
    assert 'parent_guardian' in text
    assert 'parent_consent_events' in text


def test_ai_materials_and_comments_have_provider_fallbacks():
    text = (ROOT / 'app.py').read_text()
    assert 'provider_text,_=ai_provider_generate' in text
    assert 'generated,_=ai_provider_generate' in text
    assert 'ai_teacher_comment' in text
    assert 'local_tutor_answer' in text


def test_result_assistant_supports_more_than_two_fixed_questions():
    text = (ROOT / 'app.py').read_text()
    block = text[text.index('@app.route("/ai/result-assistant"'):text.index('@app.route("/ai/learning-materials"')]
    assert 'Which classes improved' in block
    assert 'declin' in block
    assert 'below' in block
