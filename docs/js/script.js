// Initialize Particles.js and set current year
document.addEventListener('DOMContentLoaded', function() {
    // Set current year in copyright
    document.getElementById('currentYear').textContent = new Date().getFullYear();
    
    // Particles.js configuration
    particlesJS('particles-js', {
        particles: {
            number: { value: 80, density: { enable: true, value_area: 800 } },
            color: { value: ["#667eea", "#764ba2", "#4a4a4a"] },
            shape: { type: "circle" },
            opacity: { value: 0.5, random: true },
            size: { value: 3, random: true },
            line_linked: {
                enable: true,
                distance: 150,
                color: "#667eea",
                opacity: 0.2,
                width: 1
            },
            move: {
                enable: true,
                speed: 2,
                direction: "none",
                random: true,
                straight: false,
                out_mode: "out",
                bounce: false
            }
        },
        interactivity: {
            detect_on: "canvas",
            events: {
                onhover: { enable: true, mode: "repulse" },
                onclick: { enable: true, mode: "push" }
            }
        },
        retina_detect: true
    });

    // Initialize Vanilla Tilt for cards
    if (typeof VanillaTilt !== 'undefined') {
        VanillaTilt.init(document.querySelectorAll("[data-tilt]"), {
            max: 15,
            speed: 400,
            glare: true,
            "max-glare": 0.2
        });
    }

    // Title interaction
    const title = document.getElementById('greyTitle');
    title.addEventListener('click', function() {
        const letters = this.textContent.split('');
        this.textContent = '';
        
        letters.forEach((letter, i) => {
            const span = document.createElement('span');
            span.textContent = letter;
            span.style.display = 'inline-block';
            span.style.animation = `bounce 0.5s ease ${i * 0.1}s`;
            this.appendChild(span);
        });

        // Reset after animation
        setTimeout(() => {
            const spans = this.querySelectorAll('span');
            spans.forEach(span => {
                span.style.animation = '';
                span.style.display = 'inline';
            });
            this.innerHTML = 'Grey<span class="mislign">M</span>isnomer';
        }, 1000);
    });

    // Add CSS for bounce animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
    `;
    document.head.appendChild(style);
});

// Toggle About Section
function toggleAbout() {
    const aboutSection = document.getElementById('about');
    const isVisible = aboutSection.style.display === 'block';
    
    aboutSection.style.display = isVisible ? 'none' : 'block';
    
    if (!isVisible) {
        aboutSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'a' || e.key === 'A') {
        toggleAbout();
    }
    if (e.key === 'Escape') {
        document.getElementById('about').style.display = 'none';
    }
});

// Responsive adjustments
window.addEventListener('resize', () => {
    // Adjust particle density on resize
    if (window.innerWidth < 768) {
        particlesJS('particles-js', {
            particles: { number: { value: 40 } }
        });
    }
});