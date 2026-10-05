def local_tutor_answer(subject, question):
    q=question.strip()
    if not q: return "Please enter a question."
    subject=(subject or "General").strip()
    return (f"AI Tutor · {subject}\n\nHere is a guided starting point for your question:\n\n"
            f"1. Identify the key idea in: {q}\n"
            "2. Work through a simple example step by step.\n"
            "3. Try a similar practice question without looking at the answer.\n\n"
            "This local tutor mode is available offline. Connect the school's approved AI provider for richer explanations, examples and adaptive practice.")
