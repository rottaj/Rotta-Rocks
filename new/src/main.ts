import './style.css'
import * as THREE from 'three';

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera( 75, window.innerWidth / window.innerHeight, 0.1, 1000 )
const renderer = new THREE.WebGLRenderer();
renderer.setSize( window.innerWidth, window.innerHeight );
document.body.appendChild( renderer.domElement );

const geometry = new THREE.BoxGeometry( 1,1,1 );
const material = new THREE.MeshBasicMaterial( { color: 0x00ff00, wireframe: false } );
const cube = new THREE.Mesh( geometry, material );
scene.add( cube );
camera.position.z = 30;

const geometryTorus = new THREE.TorusGeometry( 10, 0.1, 16, 100 )
const geometryTorusTwo = new THREE.TorusGeometry( 10, 0.1, 16, 100 )
const torus = new THREE.Mesh( geometryTorus, material )
const torusTwo = new THREE.Mesh( geometryTorusTwo, material )
//torusTwo.translate(1, 0, 0)
const torusThree = new THREE.Mesh( geometryTorus, material )
scene.add(torus)
scene.add(torusTwo)
scene.add(torusThree)

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


const loader = new FontLoader();

loader.load( 'fonts/helvetiker_bold.typeface.json', function ( font: any ) {

	const geometry = new TextGeometry( 'Hello three.js!', {
		font: font,
		size: 80,
		height: 5,
		curveSegments: 12,
		bevelEnabled: true,
		bevelThickness: 10,
		bevelSize: 8,
		bevelOffset: 0,
		bevelSegments: 5
	} );
} );

function animate() {
  requestAnimationFrame( animate )
  cube.rotation.x += 0.01
  cube.rotation.y += 0.01
  cube.rotation.z += 0.01
  torus.rotation.x += 0.01
  torus.rotation.y += 0.01
  torus.rotation.z += 0.01
  torusTwo.rotation.x += 0.01
  torusTwo.rotation.y += 0.01
  torusTwo.rotation.z += 0.01
  torusThree.rotation.x += 0.01
  torusThree.rotation.y += 0.01
  torusThree.rotation.z += 0.01
  renderer.render( scene, camera )
}
animate()