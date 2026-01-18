const hero = document.querySelector(".hero");

document.addEventListener("mousemove", (e) => {
  const x = (e.clientX / window.innerWidth - 0.5) * 10;
  const y = (e.clientY / window.innerHeight - 0.5) * 10;

  hero.style.transform = `
    perspective(800px)
    rotateX(${-y}deg)
    rotateY(${x}deg)
  `;
});

document.addEventListener("mouseleave", () => {
  hero.style.transform = "none";
});
