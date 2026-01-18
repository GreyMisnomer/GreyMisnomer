document.addEventListener('mousemove', (e) => {
    const hero = document.querySelector('.hero');
    const width = window.innerWidth;
    const height = window.innerHeight;
    
    // Calculate mouse position relative to center (-1 to 1)
    const xVal = (e.clientX - width / 2) / width;
    const yVal = (e.clientY - height / 2) / height;

    // Move the "Red" and "Blue" layers in opposite directions
    // to create a "misnomer" visual verification effect
    const redShiftX = xVal * 15; 
    const redShiftY = yVal * 15;
    const blueShiftX = xVal * -15; 
    const blueShiftY = yVal * -15;

    // Apply the shifts to pseudo-elements via CSS variables would be complex,
    // so we manipulate text-shadow for a smoother, dep-free effect
    hero.style.textShadow = `
        ${redShiftX}px ${redShiftY}px 0px rgba(255,0,0,0.5),
        ${blueShiftX}px ${blueShiftY}px 0px rgba(0,255,255,0.5)
    `;
});