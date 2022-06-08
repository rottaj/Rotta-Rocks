import './style.css'
import * as THREE from 'three';

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera( 75, window.innerWidth / window.innerHeight, 0.1, 1000 )
const renderer = new THREE.WebGLRenderer( {alpha: true  } );
renderer.setSize( window.innerWidth, window.innerHeight );
document.body.appendChild( renderer.domElement );

const geometry = new THREE.BoxGeometry( 5,5,5 );
var texture = new THREE.TextureLoader().load( './my-mayc-4502.png' );
//const material = new THREE.MeshBasicMaterial( { color: 0x00ff00, wireframe: true } );
const material = new THREE.MeshBasicMaterial( { map: texture } );
const cube = new THREE.Mesh( geometry, material );
scene.add( cube );
camera.position.z = 30;

//const geometryTorus = new THREE.TorusGeometry( 10, 0.1, 16, 100 )
//const torus = new THREE.Mesh( geometryTorus, material )
///scene.add(torus)

const pointLight = new THREE.PointLight(0xffffff);
pointLight.position.set(20, 20, 20);
scene.add(pointLight);

function moveCamera() {
  const t = document.body.getBoundingClientRect().top;
  /*
  torus.rotation.x += 0.05;
  torus.rotation.y += 0.075;
  torus.rotation.z += 0.05;
  */
  //camera.position.z = t * -0.01;
  camera.position.x = t * -0.0002;
  camera.rotation.y = t * -0.0002;
}

document.body.onscroll = moveCamera;
moveCamera();

var mouse = {x: 0, y: 0};
function onMouseMove(event) {
  event.preventDefault();
	mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
	mouse.y = - (event.clientY / window.innerHeight) * 2 + 1;

 // Make the sphere follow the mouse
  var vector = new THREE.Vector3(mouse.x, mouse.y, 0.5);
	vector.unproject( camera );
	var dir = vector.sub( camera.position ).normalize();
	var distance = - camera.position.z / dir.z;
	var pos = camera.position.clone().add( dir.multiplyScalar( distance ) );
	cube.position.copy(pos);
}

document.addEventListener('mousemove', onMouseMove, false)

function animate() {
  requestAnimationFrame( animate )
  cube.rotation.x += 0.01
  cube.rotation.y += 0.01
  cube.rotation.z += 0.01
  /*
  torus.rotation.x += 0.01
  torus.rotation.y += 0.01
  torus.rotation.z += 0.01
  */
  renderer.render( scene, camera )
}
animate()
