const hero = document.querySelector('.hero');

hero.addEventListener('pointermove', (e) => {
  const rect = hero.getBoundingClientRect();
  const x = (e.clientX - rect.left) / rect.width - 0.5;
  const y = (e.clientY - rect.top) / rect.height - 0.5;

  hero.style.transform = `
    perspective(1200px)
    rotateX(${y * 12}deg)
    rotateY(${x * -18}deg)
    scale(1.02)
  `;
});

hero.addEventListener('pointerleave', () => {
  hero.style.transform = 'perspective(1200px) rotateX(0deg) rotateY(0deg) scale(1)';
});

// Optional tiny pulse on click/tap
hero.addEventListener('click', () => {
  hero.style.animation = 'none';
  void hero.offsetWidth;
  hero.style.animation = 'pulse 0.6s ease';
});