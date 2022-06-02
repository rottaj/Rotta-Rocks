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
camera.position.z = 25;

const geometryTwo = new THREE.TorusGeometry( 10, 3, 16, 100 )
const torus = new THREE.Mesh( geometryTwo, material )
scene.add(torus)

const pointLight = new THREE.PointLight(0xffffff);
pointLight.position.set(20, 20, 20);
scene.add(pointLight);

function animate() {
  requestAnimationFrame( animate )
  cube.rotation.x += 0.01
  cube.rotation.y += 0.01
  cube.rotation.z += 0.01
  torus.rotation.x += 0.01
  torus.rotation.y += 0.01
  torus.rotation.z += 0.01
  renderer.render( scene, camera )
}
animate()