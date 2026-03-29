from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST
from .crypto_engine import (
    rsa_full,
    ecc_full,
    aes_full,
    kyber_full,
    dilithium_full
)
from .models import CryptoExperiment
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import time   # ✅ needed for encryption timing

# ------- Base View ------
def base(request):
    return render(request, "base.html")

# ------- Dashboard ------
def dashboard(request):
    return render(request, "dashboard.html")

# ------- Experiment View ------
def experiment(request):
    if request.method == "POST":
        algorithm = request.POST.get("algorithm")

        if algorithm == "RSA":
            keysize         = request.POST.get("rsa_keysize", "2048")
            display_keysize = f"{keysize} bits"

        elif algorithm == "AES":
            keysize         = request.POST.get("aes_keysize", "256")
            display_keysize = f"{keysize} bits"

        elif algorithm == "ECC":
            keysize         = request.POST.get("curve", "P-256")
            display_keysize = f"Curve: {keysize}"

        else:   # KYBER, DILITHIUM
            keysize         = "default"
            display_keysize = "Default (Post-Quantum)"

        curve = request.POST.get("curve", "P-256")

        request.session["algorithm"]       = algorithm
        request.session["keysize"]         = keysize
        request.session["display_keysize"] = display_keysize
        request.session["curve"]           = curve

        return redirect("secure")

    return render(request, "experiment.html")

# ------- Secure Message View ------
def secure_message(request):
    algorithm = request.session.get("algorithm")

    if not algorithm:
        return redirect("experiment")

    if request.method == "GET":
        return render(request, "secure_message.html", {
            "algorithm": algorithm,
            "keysize":   request.session.get("display_keysize", ""),
        })

    message       = request.POST.get("message", "")
    shared_secret = "N/A"

    public_key = private_key = encrypted = decrypted = None

    # ✅ FIX: measure encryption time properly
    t_start = time.perf_counter()

    if algorithm == "RSA":
        rsa_bits = int(request.session.get("keysize", 2048))
        public_key, private_key, encrypted, decrypted = rsa_full(message, rsa_bits)

    elif algorithm == "ECC":
        public_key, private_key, encrypted, decrypted = ecc_full(message)
        shared_secret = "ECDH Derived Secret (used as AES key)"

    elif algorithm == "AES":
        aes_bits  = int(request.session.get("keysize", 256))
        aes_bytes = aes_bits // 8
        secret_key, encrypted, decrypted = aes_full(message, aes_bytes)
        public_key  = secret_key
        private_key = "N/A"

    elif algorithm == "KYBER":
        public_key, private_key, encrypted, decrypted = kyber_full(message)

    elif algorithm == "DILITHIUM":
        public_key, private_key, encrypted, decrypted = dilithium_full(message)

    t_end = time.perf_counter()
    encryption_time = t_end - t_start   # seconds as float

    # ✅ Save to performance log with correct key_size
    raw_keysize = request.session.get("keysize", "default")
    try:
        key_size_int = int(raw_keysize)
    except (ValueError, TypeError):
        key_size_int = 0   # ECC curve / PQ default → store 0

    CryptoExperiment.objects.create(
        algorithm       = algorithm,
        key_generation_time = 0.0,
        encryption_time = encryption_time,
        key_size        = key_size_int,
        message_size    = len(message),
        generated_key   = public_key or "",
        encrypted_message = encrypted or "",
    )

    return render(request, "result.html", {
        "algorithm":     algorithm,
        "keysize":       request.session.get("display_keysize", "Default"),
        "curve":         request.session.get("curve", "P-256"),
        "public_key":    public_key,
        "private_key":   private_key,
        "encrypted":     encrypted,
        "decrypted":     decrypted,
        "shared_secret": shared_secret,
    })


# ------- Analytics View ------
def analytics(request):
    experiments = CryptoExperiment.objects.all().order_by('-created_at')
    return render(request, "analytics.html", {"experiments": experiments})


# ✅ NEW: Delete a single log entry
@require_POST
def delete_log(request, pk):
    entry = get_object_or_404(CryptoExperiment, pk=pk)
    entry.delete()
    return redirect("analytics")


















