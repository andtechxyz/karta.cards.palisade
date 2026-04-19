import { Routes, Route } from 'react-router-dom';
import Activate from './pages/Activate';

export default function App() {
  return (
    <div className="app">
      <Routes>
        <Route path="/activate" element={<Activate />} />
        <Route
          path="*"
          element={
            <div className="page">
              <h1>Tap your card</h1>
              <div className="panel">
                <p className="small">
                  Hold your Palisade card against the back of your phone to begin
                  activation.
                </p>
              </div>
            </div>
          }
        />
      </Routes>
    </div>
  );
}
